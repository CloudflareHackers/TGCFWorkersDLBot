/**
 * Browser WebSocket adapter for teleproto.
 * 
 * teleproto only ships PromisedNetSockets (Node.js TCP).
 * This provides a browser-compatible WebSocket transport that matches
 * the same interface, so it can be passed as `networkSocket` param.
 * 
 * Also maps Telegram DC IP addresses → WebSocket hostnames automatically.
 */

const closeError = new Error('WebSocket was closed');

// Telegram DC IP → WebSocket hostname mapping
// Includes both primary and download (-1) DC IPs
const DC_IP_TO_WS_HOST = {
  // DC1
  '149.154.175.53': 'pluto.web.telegram.org',
  '149.154.175.54': 'pluto.web.telegram.org',
  // DC2
  '149.154.167.50': 'venus.web.telegram.org',
  '149.154.167.51': 'venus.web.telegram.org',
  '149.154.167.40': 'venus.web.telegram.org',
  '149.154.167.41': 'venus.web.telegram.org',
  // DC3
  '149.154.175.100': 'aurora.web.telegram.org',
  '149.154.175.101': 'aurora.web.telegram.org',
  // DC4
  '149.154.167.91': 'vesta.web.telegram.org',
  '149.154.167.92': 'vesta.web.telegram.org',
  '149.154.167.90': 'vesta.web.telegram.org',
  // DC5
  '149.154.171.5': 'flora.web.telegram.org',
  '149.154.171.6': 'flora.web.telegram.org',
  '91.108.56.100': 'flora.web.telegram.org',
  '91.108.56.101': 'flora.web.telegram.org',
  // Additional known IPs
  '91.108.56.130': 'vesta.web.telegram.org',
  '91.108.4.204': 'venus-1.web.telegram.org',
};

// Also match by DC ID (used as fallback)
const DC_ID_TO_WS_HOST = {
  1: 'pluto.web.telegram.org',
  2: 'venus.web.telegram.org',
  3: 'aurora.web.telegram.org',
  4: 'vesta.web.telegram.org',
  5: 'flora.web.telegram.org',
};

// Simple mutex using a promise chain
let mutexPromise = Promise.resolve();
function acquireMutex() {
  let release;
  const prev = mutexPromise;
  mutexPromise = new Promise((resolve) => { release = resolve; });
  return prev.then(() => release);
}

export class PromisedWebSockets {
  constructor() {
    this.client = undefined;
    this.stream = Buffer.alloc(0);
    this.closed = true;
    this.canRead = undefined;
    this.resolveRead = undefined;
    this.website = undefined;
  }

  async readExactly(number) {
    let readData = Buffer.alloc(0);
    while (true) {
      const thisTime = await this.read(number);
      readData = Buffer.concat([readData, thisTime]);
      number = number - thisTime.length;
      if (!number) {
        return readData;
      }
    }
  }

  async read(number) {
    if (this.closed) {
      throw closeError;
    }
    await this.canRead;
    if (this.closed) {
      throw closeError;
    }
    const toReturn = this.stream.slice(0, number);
    this.stream = this.stream.slice(number);
    if (this.stream.length === 0) {
      this.canRead = new Promise((resolve) => {
        this.resolveRead = resolve;
      });
    }
    return toReturn;
  }

  async readAll() {
    if (this.closed || !(await this.canRead)) {
      throw closeError;
    }
    const toReturn = this.stream;
    this.stream = Buffer.alloc(0);
    this.canRead = new Promise((resolve) => {
      this.resolveRead = resolve;
    });
    return toReturn;
  }

  /**
   * Resolve a Telegram DC IP address to its WebSocket hostname.
   * Falls back to a generic Telegram WebSocket host for unknown IPs.
   */
  resolveHost(ip) {
    // If it's already a hostname (contains letters), use it directly
    if (/[a-zA-Z]/.test(ip)) return ip;
    // Check our known mapping
    if (DC_IP_TO_WS_HOST[ip]) return DC_IP_TO_WS_HOST[ip];
    // For any unknown Telegram IP (149.154.* or 91.108.*), use a generic WS host
    // All Telegram WebSocket endpoints route to the correct DC internally
    if (ip.startsWith('149.154.') || ip.startsWith('91.108.')) {
      console.warn(`[WS] Unknown Telegram IP ${ip}, using venus.web.telegram.org as fallback`);
      return 'venus.web.telegram.org';
    }
    return ip;
  }

  getWebSocketLink(ip, port) {
    const host = this.resolveHost(ip);
    // Always use WSS (port 443) for Telegram WebSocket servers
    return `wss://${host}:443/apiws`;
  }

  async connect(port, ip) {
    this.stream = Buffer.alloc(0);
    this.canRead = new Promise((resolve) => {
      this.resolveRead = resolve;
    });
    this.closed = false;
    this.website = this.getWebSocketLink(ip, port);
    this.client = new WebSocket(this.website, 'binary');
    this.client.binaryType = 'arraybuffer';

    return new Promise((resolve, reject) => {
      if (this.client) {
        this.client.onopen = () => {
          this.receive();
          resolve(this);
        };
        this.client.onerror = (error) => {
          reject(error);
        };
        this.client.onclose = () => {
          if (this.resolveRead) {
            this.resolveRead(false);
          }
          this.closed = true;
        };
        // Handle browser offline events
        if (typeof window !== 'undefined') {
          window.addEventListener('offline', async () => {
            await this.close();
            if (this.resolveRead) {
              this.resolveRead(false);
            }
          });
        }
      }
    });
  }

  write(data) {
    if (this.closed) {
      throw closeError;
    }
    if (this.client) {
      this.client.send(data);
    }
  }

  async close() {
    if (this.client) {
      try { this.client.close(); } catch {}
    }
    this.closed = true;
  }

  async receive() {
    if (this.client) {
      this.client.onmessage = async (message) => {
        const release = await acquireMutex();
        try {
          let data;
          if (message.data instanceof ArrayBuffer) {
            data = Buffer.from(message.data);
          } else if (message.data instanceof Blob) {
            data = Buffer.from(await message.data.arrayBuffer());
          } else {
            data = Buffer.from(message.data);
          }
          this.stream = Buffer.concat([this.stream, data]);
          if (this.resolveRead) {
            this.resolveRead(true);
          }
        } finally {
          release();
        }
      };
    }
  }

  toString() {
    return 'PromisedWebSocket';
  }
}

/**
 * Resolve a DC ID to a WebSocket-compatible hostname.
 * Can be used to configure sessions with the right initial address.
 */
export function getDCWebSocketHost(dcId) {
  return DC_ID_TO_WS_HOST[dcId] || DC_ID_TO_WS_HOST[4];
}
