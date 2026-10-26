/* Incremental SHA-256, FIPS 180-4. Constant memory: 2 MiB per slice.
   No file bytes leave this worker. Main thread remains responsive. */
'use strict';
class SHA256 {
    constructor() {
        this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
        this.buf = new Uint8Array(64);
        this.used = 0;
        this.length = 0;
        this.w = new Uint32Array(64);
    }
    block(b) {
        const w = this.w;
        for (let i = 0; i < 16; i++) w[i] = (b[i * 4] << 24) | (b[i * 4 + 1] << 16) | (b[i * 4 + 2] << 8) | b[i * 4 + 3];
        const rr = (v, n) => (v >>> n) | (v << (32 - n));
        for (let i = 16; i < 64; i++) {
            const x = w[i - 15], y = w[i - 2];
            w[i] = (w[i - 16] + (rr(x, 7) ^ rr(x, 18) ^ (x >>> 3)) + w[i - 7] + (rr(y, 17) ^ rr(y, 19) ^ (y >>> 10))) >>> 0;
        }
        let [a, c, d, e, f, g, h, j] = this.h;
        for (let i = 0; i < 64; i++) {
            const t1 = (j + (rr(f, 6) ^ rr(f, 11) ^ rr(f, 25)) + ((f & g) ^ (~f & h)) + SHA256.K[i] + w[i]) >>> 0;
            const t2 = ((rr(a, 2) ^ rr(a, 13) ^ rr(a, 22)) + ((a & c) ^ (a & d) ^ (c & d))) >>> 0;
            j = h; h = g; g = f; f = (e + t1) >>> 0; e = d; d = c; c = a; a = (t1 + t2) >>> 0;
        }
        [a, c, d, e, f, g, h, j].forEach((v, i) => this.h[i] = (this.h[i] + v) >>> 0);
    }
    update(bytes) {
        this.length += bytes.length;
        let i = 0;
        if (this.used) {
            while (i < bytes.length && this.used < 64) this.buf[this.used++] = bytes[i++];
            if (this.used === 64) { this.block(this.buf); this.used = 0; }
        }
        while (i + 64 <= bytes.length) { this.block(bytes.subarray(i, i + 64)); i += 64; }
        while (i < bytes.length) this.buf[this.used++] = bytes[i++];
        return this;
    }
    digest() {
        const n = this.length;
        this.buf[this.used++] = 128;
        if (this.used > 56) { this.buf.fill(0, this.used); this.block(this.buf); this.used = 0; }
        this.buf.fill(0, this.used, 56);
        const v = new DataView(this.buf.buffer);
        v.setUint32(56, Math.floor(n / 0x20000000), false);
        v.setUint32(60, (n * 8) >>> 0, false);
        this.block(this.buf);
        return Array.from(this.h, v => v.toString(16).padStart(8, '0')).join('');
    }
}
SHA256.K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
self.onmessage = async e => {
    try {
        const file = e.data.file;
        const hash = new SHA256();
        const chunk = 2 * 1024 * 1024;
        for (let offset = 0; offset < file.size; offset += chunk) {
            hash.update(new Uint8Array(await file.slice(offset, offset + chunk).arrayBuffer()));
            self.postMessage({ progress: Math.min(100, Math.round((offset + chunk) / file.size * 100)) });
        }
        self.postMessage({ hash: hash.digest() });
    } catch {
        self.postMessage({ error: 'Dosya okunamadı.' });
    }
};
