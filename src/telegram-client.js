/**
 * Telegram MTProto Client wrapper using GramJS.
 * Runs entirely in the browser - connections via WebSocket.
 * Authenticates as a bot using bot token.
 * Downloads files with NO size limit (unlike Bot API's 20MB cap).
 * Supports PARALLEL chunk downloads for faster speeds.
 */

import { TelegramClient, Api } from 'telegram';
import { utils } from 'telegram';
import { NewMessage } from 'telegram/events';
import bigInt from 'big-integer';

/**
 * Expose the Api namespace so main.js can reconstruct file locations
 * from stored IDs without importing 'telegram' directly.
 */
export function getApi() {
  return Api;
}

import { getSettings } from './settings.js';

const CREDENTIALS_KEY = 'tg_credentials';
const MIN_PARALLEL_SIZE = 1024 * 1024; // 1MB - minimum for parallel mode

export class TGDownloader {
  constructor(onLog, onProgress) {
    this.client = null;
    this.onLog = onLog || (() => {});
    this.onProgress = onProgress || (() => {});
    this.connected = false;
    this._fileCache = new Map(); // Cache file info by link
  }

  // ===== CONNECTION =====

  async connect(apiId, apiHash, botToken) {
    try {
      this.onLog('info', 'Initializing MTProto connection...');
      this._credentials = { apiId, apiHash, botToken };
      this.client = new TelegramClient('tg_bot', parseInt(apiId), apiHash, {
        connectionRetries: 10,
        retryDelay: 2000,
        autoReconnect: true,
        useWSS: true,
      });
      this.onLog('info', 'Connecting to Telegram servers...');
      await this.client.start({ botAuthToken: botToken });
      localStorage.setItem(CREDENTIALS_KEY, JSON.stringify({ apiId, apiHash, botToken }));
      this.connected = true;
      const me = await this.client.getMe();
      this.onLog('success', `Connected as @${me.username} (${me.firstName})`);
      this.onLog('dim', `Session saved. Will reconnect faster next time.`);
      
      // Monitor connection state
      this._startConnectionMonitor();
      
      // Fetch missed updates (messages sent while offline)
      if (this._onPendingUpdatesReady) {
        this._fetchPendingUpdates();
      }
      
      return { success: true, botInfo: me };
    } catch (error) {
      this.connected = false;
      this.onLog('error', `Connection failed: ${error.message}`);
      throw error;
    }
  }

  async disconnect() {
    this._stopConnectionMonitor();
    if (this.client) {
      try { await this.client.disconnect(); } catch {}
      this.client = null;
      this.connected = false;
      this.onLog('info', 'Disconnected from Telegram.');
    }
  }

  /**
   * Attempt to reconnect using saved credentials.
   * Returns true if successful.
   */
  async reconnect() {
    if (this.connected && this.client) {
      // Check if actually connected by pinging
      try {
        await this.client.getMe();
        return true;
      } catch {
        this.connected = false;
      }
    }

    const creds = this._credentials || this.getSavedCredentials();
    if (!creds) {
      this.onLog('error', 'No saved credentials to reconnect.');
      return false;
    }

    this.onLog('info', '🔄 Reconnecting...');
    try {
      await this.connect(creds.apiId, creds.apiHash, creds.botToken);
      return true;
    } catch (e) {
      this.onLog('error', `Reconnect failed: ${e.message}`);
      return false;
    }
  }

  /**
   * Ensure connection is alive before performing an operation.
   * Auto-reconnects if disconnected.
   */
  async ensureConnected() {
    if (this.connected && this.client) {
      try {
        // Quick ping to verify connection
        await this.client.invoke(new Api.Ping({ pingId: bigInt(Date.now()) }));
        return true;
      } catch {
        this.connected = false;
        this.onLog('warn', 'Connection lost. Attempting auto-reconnect...');
      }
    }
    return this.reconnect();
  }

  _startConnectionMonitor() {
    this._stopConnectionMonitor();
    this._connectionMonitor = setInterval(async () => {
      if (!this.connected || !this.client) return;
      try {
        // Silent health check every 30s
        if (this.client._sender && !this.client._sender._userConnected) {
          this.connected = false;
          if (this.onConnectionLost) this.onConnectionLost();
          this.onLog('warn', '⚠️ Connection lost. Will auto-reconnect on next action.');
        }
      } catch {}
    }, 30000);
  }

  _stopConnectionMonitor() {
    if (this._connectionMonitor) {
      clearInterval(this._connectionMonitor);
      this._connectionMonitor = null;
    }
  }

  getSavedCredentials() {
    try {
      const saved = localStorage.getItem(CREDENTIALS_KEY);
      return saved ? JSON.parse(saved) : null;
    } catch { return null; }
  }

  clearSession() {
    localStorage.removeItem(CREDENTIALS_KEY);
    this._fileCache.clear();
    for (let i = localStorage.length - 1; i >= 0; i--) {
      const key = localStorage.key(i);
      if (key && key.startsWith('tg_bot:')) localStorage.removeItem(key);
    }
  }

  // ===== FETCH FILE INFO (cached) =====

  /**
   * Fetch message and extract file location info. Results are cached by link key.
   * Returns a reusable fileRef object for downloading (no need to re-fetch).
   */
  async fetchFileInfo(chatIdentifier, messageId, cacheKey) {
    if (!this.client || !this.connected) {
      throw new Error('Not connected. Please connect first.');
    }

    // Check cache first
    if (cacheKey && this._fileCache.has(cacheKey)) {
      this.onLog('dim', 'Using cached file info (no re-fetch needed).');
      return this._fileCache.get(cacheKey);
    }

    this.onLog('info', `Fetching message #${messageId}...`);

    // Resolve entity
    let entity;
    if (typeof chatIdentifier === 'string' && !chatIdentifier.startsWith('-')) {
      this.onLog('dim', `Resolving @${chatIdentifier}...`);
      entity = await this.client.getEntity(chatIdentifier);
    } else {
      const id = typeof chatIdentifier === 'bigint' ? chatIdentifier : BigInt(chatIdentifier);
      this.onLog('dim', `Resolving channel ID ${id}...`);
      entity = await this.client.getEntity(id);
    }

    // Fetch message
    const result = await this.client.getMessages(entity, { ids: [messageId] });
    if (!result || result.length === 0 || !result[0]) {
      throw new Error(`Message #${messageId} not found. Make sure the bot has access.`);
    }

    const message = result[0];
    const media = message.media;
    if (!media) throw new Error('This message has no media.');

    // Extract file metadata
    let fileName = 'unknown';
    let fileSize = 0;
    let mimeType = '';
    let fileLocation = null;
    let dcId = null;

    if (media.document) {
      const doc = media.document;
      fileSize = Number(doc.size);
      mimeType = doc.mimeType || '';
      dcId = doc.dcId;

      for (const attr of doc.attributes || []) {
        if (attr.className === 'DocumentAttributeFilename') {
          fileName = attr.fileName;
        }
      }
      if (fileName === 'unknown' && mimeType) {
        fileName = `file_${message.id}.${mimeType.split('/')[1] || 'bin'}`;
      }

      // Create the reusable InputDocumentFileLocation
      fileLocation = new Api.InputDocumentFileLocation({
        id: doc.id,
        accessHash: doc.accessHash,
        fileReference: doc.fileReference,
        thumbSize: '',
      });
    } else if (media.photo) {
      const photo = media.photo;
      const sizes = photo.sizes || [];
      const largest = sizes[sizes.length - 1];
      fileSize = largest && largest.size ? Number(largest.size) : 0;
      mimeType = 'image/jpeg';
      fileName = `photo_${message.id}.jpg`;
      dcId = photo.dcId;

      fileLocation = new Api.InputPhotoFileLocation({
        id: photo.id,
        accessHash: photo.accessHash,
        fileReference: photo.fileReference,
        thumbSize: largest ? largest.type : '',
      });
    }

    if (!fileLocation) {
      throw new Error('Could not extract file location from message.');
    }

    const fileRef = {
      fileName,
      fileSize,
      mimeType,
      fileLocation,
      dcId,
      message, // keep reference for fallback
      hasMedia: true,
    };

    // Cache it
    if (cacheKey) {
      this._fileCache.set(cacheKey, fileRef);
    }

    this.onLog('success', `File: ${fileName} (${this._formatSize(fileSize)}) [${mimeType}]`);
    return fileRef;
  }

  // ===== DOWNLOAD =====

  /**
   * Download a file using cached fileRef.
   * @param {object} fileRef - from fetchFileInfo()
   * @param {number} connections - parallel connections (1-8)
   */
  async downloadFile(fileRef, connectionsOverride) {
    // Auto-reconnect if needed
    if (!this.connected || !this.client) {
      this.onLog('warn', 'Not connected. Attempting auto-reconnect...');
      const ok = await this.reconnect();
      if (!ok) throw new Error('Not connected and auto-reconnect failed.');
    }

    // Read settings for workers (use override if provided, else settings)
    const settings = getSettings();
    let connections = connectionsOverride || settings.parallelWorkers || 8;
    connections = Math.min(Math.max(1, connections), 32);
    const { fileSize, fileName, mimeType, fileLocation, dcId } = fileRef;

    // For small files or single connection, use simple download
    // Note: _downloadSingle requires a live message object (uses downloadMedia).
    // Restored files from IndexedDB only have fileLocation, so they must use parallel path.
    if ((connections <= 1 || fileSize < MIN_PARALLEL_SIZE) && fileRef.message) {
      this.onLog('info', `Downloading ${fileName} [1 connection]...`);
      return this._downloadSingle(fileRef);
    }

    // If no message object (restored file), force at least 1-connection parallel (uses fileLocation directly)
    if (!fileRef.message) {
      connections = Math.max(connections, 1);
      this.onLog('info', `Downloading ${fileName} [${connections} conn, reconstructed ref]...`);
    }

    // Parallel download
    this.onLog('info', `Downloading ${fileName} [${connections} connections]...`);
    return this._downloadParallel(fileRef, connections);
  }

  /**
   * Single-connection download using GramJS downloadMedia (simple, reliable)
   */
  async _downloadSingle(fileRef) {
    const startTime = Date.now();
    let lastUpdate = 0;

    const buffer = await this.client.downloadMedia(fileRef.message, {
      progressCallback: (downloaded, total) => {
        const now = Date.now();
        if (now - lastUpdate < 200 && downloaded < total) return;
        lastUpdate = now;
        this._emitProgress(startTime, Number(downloaded), Number(total));
      },
    });

    if (!buffer) throw new Error('Download returned empty data.');
    return this._finishDownload(buffer, fileRef, startTime);
  }

  /**
   * PARALLEL multi-connection download.
   * Uses upload.GetFile with different offsets via multiple DC senders.
   * Each worker downloads a range of the file simultaneously.
   */
  async _downloadParallel(fileRef, connections) {
    const { fileSize, fileLocation, dcId } = fileRef;
    const startTime = Date.now();

    // Read chunk size from settings (auto-tuned or manual)
    const dlSettings = getSettings();
    const MAX_CHUNK_SIZE = (dlSettings.autoChunkSize && dlSettings.bestChunkSize) || dlSettings.chunkSize || 524288;

    // Calculate chunk distribution
    const totalChunks = Math.ceil(fileSize / MAX_CHUNK_SIZE);
    const actualConnections = Math.min(connections, totalChunks);
    const chunksPerWorker = Math.ceil(totalChunks / actualConnections);

    // Cap unique DC senders to avoid overwhelming the connection.
    // Workers > maxSenders will share senders round-robin.
    const maxSenders = Math.min(actualConnections, 8);
    this.onLog('dim', `${totalChunks} chunks (${this._formatSize(MAX_CHUNK_SIZE)} each), ${actualConnections} workers, ${maxSenders} DC connections`);

    // Get senders (each creates a separate connection to the DC)
    const senders = [];
    try {
      for (let i = 0; i < maxSenders; i++) {
        const sender = await this.client.getSender(dcId);
        senders.push(sender);
      }
    } catch (e) {
      this.onLog('warn', `Could only create ${senders.length} senders: ${e.message}`);
      if (senders.length === 0) {
        if (fileRef.message) {
          this.onLog('warn', 'Falling back to single-connection download...');
          return this._downloadSingle(fileRef);
        }
        throw new Error('Could not create any DC senders for download.');
      }
    }

    // Track progress per worker
    const workerProgress = new Array(actualConnections).fill(0);

    // Create download tasks
    const tasks = [];
    for (let i = 0; i < actualConnections; i++) {
      const startChunk = i * chunksPerWorker;
      const endChunk = Math.min(startChunk + chunksPerWorker, totalChunks);
      if (startChunk >= totalChunks) break;

      const startOffset = startChunk * MAX_CHUNK_SIZE;
      const endOffset = Math.min(endChunk * MAX_CHUNK_SIZE, fileSize);

      tasks.push(
        this._downloadRange(
          fileLocation,
          senders[i % senders.length],
          startOffset,
          endOffset,
          i,
          workerProgress,
          startTime,
          fileSize,
          MAX_CHUNK_SIZE
        )
      );
    }

    // Run all workers in parallel
    let results;
    try {
      results = await Promise.all(tasks);
    } catch (e) {
      if (fileRef.message) {
        this.onLog('warn', `Parallel download failed: ${e.message}. Retrying single...`);
        return this._downloadSingle(fileRef);
      }
      throw new Error(`Download failed: ${e.message}`);
    }

    // Merge all chunks in order into one buffer
    const totalBytes = results.reduce((sum, buf) => sum + buf.length, 0);
    const merged = new Uint8Array(totalBytes);
    let offset = 0;
    for (const chunk of results) {
      merged.set(new Uint8Array(chunk.buffer || chunk), offset);
      offset += chunk.length;
    }

    return this._finishDownload(Buffer.from(merged), fileRef, startTime);
  }

  /**
   * Download a byte range using low-level upload.GetFile.
   * Each call downloads from startOffset to endOffset in 512KB chunks.
   */
  async _downloadRange(fileLocation, sender, startOffset, endOffset, workerIdx, workerProgress, startTime, totalFileSize, chunkSize) {
    const chunks = [];
    let currentOffset = startOffset;
    let retries = 0;
    const MAX_RETRIES = 3;

    while (currentOffset < endOffset) {
      // Limit MUST be a multiple of 4096 and max 1MB for MTProto
      const limit = chunkSize;

      const request = new Api.upload.GetFile({
        location: fileLocation,
        offset: bigInt(currentOffset),
        limit: limit,
      });

      let result;
      try {
        result = await this.client.invokeWithSender(request, sender);
        retries = 0; // Reset retries on success
      } catch (e) {
        if (e.message && e.message.includes('FILE_MIGRATE_')) {
          // File is on another DC
          const newDc = parseInt(e.message.match(/\d+/)?.[0] || '0');
          if (newDc) {
            this.onLog('dim', `Worker ${workerIdx + 1}: migrating to DC${newDc}`);
            sender = await this.client.getSender(newDc);
            result = await this.client.invokeWithSender(request, sender);
          } else {
            throw e;
          }
        } else if (retries < MAX_RETRIES) {
          // Connection error — wait and retry with a fresh sender
          retries++;
          this.onLog('warn', `Worker ${workerIdx + 1}: error at offset ${currentOffset}, retry ${retries}/${MAX_RETRIES}...`);
          await new Promise(r => setTimeout(r, 1000 * retries)); // Exponential backoff
          try {
            sender = await this.client.getSender(undefined); // Get a fresh sender
          } catch {
            // If getSender fails, wait more and try once more
            await new Promise(r => setTimeout(r, 3000));
            sender = await this.client.getSender(undefined);
          }
          continue; // Retry the same offset
        } else {
          throw e;
        }
      }

      const bytes = result.bytes;
      chunks.push(bytes);
      currentOffset += bytes.length;

      // Update progress
      workerProgress[workerIdx] = currentOffset - startOffset;
      const totalDownloaded = workerProgress.reduce((a, b) => a + b, 0);
      this._emitProgress(startTime, totalDownloaded, totalFileSize);

      // If we got less than requested (and less than chunkSize), we've reached the end
      if (bytes.length < chunkSize) break;
    }

    // Merge this worker's chunks
    const totalLen = chunks.reduce((sum, c) => sum + c.length, 0);
    const merged = Buffer.alloc(totalLen);
    let pos = 0;
    for (const chunk of chunks) {
      chunk.copy ? chunk.copy(merged, pos) : merged.set(new Uint8Array(chunk), pos);
      pos += chunk.length;
    }

    this.onLog('dim', `Worker ${workerIdx + 1}: done (${this._formatSize(totalLen)})`);
    return merged;
  }

  // ===== INCOMING MESSAGE LISTENER =====

  /**
   * Start listening for incoming messages with media.
   * Calls onFileReceived(fileRef) whenever a file/media message arrives.
   */
  startListening(onFileReceived) {
    if (!this.client || !this.connected) {
      this.onLog('error', 'Not connected. Cannot listen for messages.');
      return;
    }

    this._onFileReceived = onFileReceived;

    // GramJS event handler for new messages
    this.client.addEventHandler(async (event) => {
      try {
        const message = event.message;
        if (!message || !message.media) return;

        // Only process documents, photos, videos
        const media = message.media;
        if (!media.document && !media.photo) return;

        // Extract file info
        let fileName = 'unknown';
        let fileSize = 0;
        let mimeType = '';
        let fileLocation = null;
        let dcId = null;

        if (media.document) {
          const doc = media.document;
          fileSize = Number(doc.size);
          mimeType = doc.mimeType || '';
          dcId = doc.dcId;

          for (const attr of doc.attributes || []) {
            if (attr.className === 'DocumentAttributeFilename') {
              fileName = attr.fileName;
            }
          }
          if (fileName === 'unknown' && mimeType) {
            fileName = `file_${message.id}.${mimeType.split('/')[1] || 'bin'}`;
          }

          fileLocation = new Api.InputDocumentFileLocation({
            id: doc.id,
            accessHash: doc.accessHash,
            fileReference: doc.fileReference,
            thumbSize: '',
          });
        } else if (media.photo) {
          const photo = media.photo;
          const sizes = photo.sizes || [];
          const largest = sizes[sizes.length - 1];
          fileSize = largest && largest.size ? Number(largest.size) : 0;
          mimeType = 'image/jpeg';
          fileName = `photo_${message.id}.jpg`;
          dcId = photo.dcId;

          fileLocation = new Api.InputPhotoFileLocation({
            id: photo.id,
            accessHash: photo.accessHash,
            fileReference: photo.fileReference,
            thumbSize: largest ? largest.type : '',
          });
        }

        if (!fileLocation) return;

        // Get chat info
        let chatName = 'Unknown';
        try {
          const peer = message.peerId;
          if (peer?.channelId) {
            chatName = `Channel -100${peer.channelId}`;
          } else if (peer?.chatId) {
            chatName = `Chat -${peer.chatId}`;
          } else if (peer?.userId) {
            chatName = `User ${peer.userId}`;
          }
        } catch {}

        const fileRef = {
          fileName,
          fileSize,
          mimeType,
          fileLocation,
          dcId,
          message,
          hasMedia: true,
          chatName,
          messageId: message.id,
          date: message.date ? new Date(message.date * 1000) : new Date(),
        };

        // Cache it
        const cacheKey = `msg_${message.id}_${dcId}`;
        this._fileCache.set(cacheKey, fileRef);

        this.onLog('info', `📨 New file: ${fileName} (${this._formatSize(fileSize)}) from ${chatName}`);

        if (this._onFileReceived) {
          this._onFileReceived(fileRef);
        }
      } catch (e) {
        // Silently ignore non-media messages
      }
    }, new NewMessage({}));

    this.onLog('success', '👂 Listening for incoming files...');
  }

  /**
   * Start listening for ALL incoming messages (text + media).
   * Calls onMessage(msgInfo) for every message received.
   */
  startMessageListener(onMessage) {
    if (!this.client || !this.connected) return;

    this._onMessage = onMessage;

    this.client.addEventHandler(async (event) => {
      try {
        const message = event.message;
        if (!message) return;

        // Determine sender type and name
        let senderType = 'User';
        let senderName = 'Unknown';
        let senderId = null;
        let chatPeer = null;

        const peer = message.peerId;
        if (peer) {
          if (peer.channelId) {
            senderType = 'Channel';
            senderId = `-100${peer.channelId}`;
            senderName = `Channel ${peer.channelId}`;
            chatPeer = peer;
          } else if (peer.chatId) {
            senderType = 'Group';
            senderId = `-${peer.chatId}`;
            senderName = `Group ${peer.chatId}`;
            chatPeer = peer;
          } else if (peer.userId) {
            senderType = 'User';
            senderId = peer.userId.toString();
            senderName = `User ${peer.userId}`;
            chatPeer = peer;
          }
        }

        // Try to resolve actual name
        try {
          if (message.sender) {
            const s = message.sender;
            if (s.firstName || s.lastName) {
              senderName = [s.firstName, s.lastName].filter(Boolean).join(' ');
            } else if (s.title) {
              senderName = s.title;
            }
            if (s.username) {
              senderName += ` (@${s.username})`;
            }
          }
        } catch {}

        const text = message.text || message.message || '';
        const hasMedia = !!(message.media && (message.media.document || message.media.photo));

        const msgInfo = {
          id: message.id,
          text,
          senderType,
          senderName,
          senderId,
          chatPeer,
          hasMedia,
          message, // raw GramJS message for download/reply
          date: message.date ? new Date(message.date * 1000) : new Date(),
        };

        if (this._onMessage) {
          this._onMessage(msgInfo);
        }
      } catch {}
    }, new NewMessage({}));
  }

  /**
   * Download a photo thumbnail as a data URL (base64).
   * Used for showing inline photo previews in chat.
   */
  async downloadPhotoThumbnail(message) {
    if (!this.client || !this.connected) return null;
    try {
      const media = message.media;
      if (!media || (!media.photo && !media.document)) return null;

      // Download small thumbnail
      const buffer = await this.client.downloadMedia(message, {
        thumb: 0, // smallest thumbnail
      });
      if (!buffer || buffer.length === 0) return null;

      // Convert to base64 data URL
      const base64 = Buffer.from(buffer).toString('base64');
      const mimeType = media.photo ? 'image/jpeg' : (media.document?.mimeType || 'image/jpeg');
      return `data:${mimeType};base64,${base64}`;
    } catch {
      return null;
    }
  }

  /**
   * Download full-size photo as blob URL.
   */
  async downloadFullPhoto(message) {
    if (!this.client || !this.connected) return null;
    try {
      const buffer = await this.client.downloadMedia(message);
      if (!buffer) return null;
      const blob = new Blob([buffer], { type: 'image/jpeg' });
      return URL.createObjectURL(blob);
    } catch {
      return null;
    }
  }

  /**
   * Send a text message reply to a chat.
   * @param {object} chatPeer - the peerId from the original message
   * @param {string} text - reply text
   * @param {number} replyToMsgId - optional message ID to reply to
   */
  async sendMessage(chatPeer, text, replyToMsgId) {
    if (!this.client || !this.connected) {
      throw new Error('Not connected.');
    }

    // Resolve entity from peer
    let entity;
    if (chatPeer.channelId) {
      entity = await this.client.getEntity(BigInt(`-100${chatPeer.channelId}`));
    } else if (chatPeer.chatId) {
      entity = await this.client.getEntity(BigInt(`-${chatPeer.chatId}`));
    } else if (chatPeer.userId) {
      entity = await this.client.getEntity(BigInt(chatPeer.userId.toString()));
    } else {
      throw new Error('Invalid chat peer.');
    }

    await this.client.sendMessage(entity, {
      message: text,
      replyTo: replyToMsgId || undefined,
    });

    this.onLog('success', `✉️ Reply sent!`);
  }

  // ===== HELPERS =====

  _finishDownload(buffer, fileRef, startTime) {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
    const avgSpeed = this._formatSize(fileRef.fileSize / (parseFloat(elapsed) || 1));
    this.onLog('success', `Download complete! (${elapsed}s, avg ${avgSpeed}/s)`);

    const blob = new Blob([buffer], { type: fileRef.mimeType || 'application/octet-stream' });
    return { blob, fileInfo: fileRef };
  }

  _emitProgress(startTime, downloadedBytes, totalBytes) {
    const now = Date.now();
    const elapsed = (now - startTime) / 1000;
    const speed = downloadedBytes / (elapsed || 1);
    const percent = totalBytes > 0 ? (downloadedBytes / totalBytes) * 100 : 0;
    const remaining = speed > 0 ? (totalBytes - downloadedBytes) / speed : 0;
    this.onProgress({
      downloaded: downloadedBytes,
      total: totalBytes,
      percent: Math.min(percent, 100),
      speed,
      elapsed,
      remaining,
    });
  }

  saveBlobAs(blob, fileName) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 30000);
    this.onLog('success', `💾 File saved: ${fileName}`);
  }

  _formatSize(bytes) {
    if (!bytes) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return (bytes / Math.pow(1024, i)).toFixed(i > 0 ? 2 : 0) + ' ' + units[i];
  }
}
