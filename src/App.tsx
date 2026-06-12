import { useState, useEffect, useRef, useCallback } from 'react';
import Peer from 'peerjs';
import {
  deriveKeys, encryptChunk, decryptChunk, hashBuffer,
  generateECDHKeyPair, exportPublicKey, importPublicKey,
  deriveECDHShared, combineKeys, zeroBuffer, CHUNK_SIZE,
  bufToHex, hexToBuf, bufToBase64, base64ToBuf
} from './crypto';
import { drawQRToCanvas } from './qrcode';
import './style.css';

type Phase = 'select' | 'link' | 'sending' | 'sent' | 'prompt' | 'receiving' | 'complete' | 'error';
type ConnState = 'idle' | 'connecting' | 'connected' | 'disconnected';

const RATCHET_INTERVAL = 100;
const ENTROPY_RATE = 0.10;

function fmtSize(bytes: number): string {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
  if (bytes < 1073741824) return (bytes / 1048576).toFixed(1) + ' MB';
  return (bytes / 1073741824).toFixed(2) + ' GB';
}

function fmtSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return bytesPerSec.toFixed(0) + ' B/s';
  if (bytesPerSec < 1048576) return (bytesPerSec / 1024).toFixed(0) + ' KB/s';
  return (bytesPerSec / 1048576).toFixed(1) + ' MB/s';
}

export default function App() {
  const [phase, setPhase] = useState<Phase>('select');
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [linkUrl, setLinkUrl] = useState('');
  const [copied, setCopied] = useState(false);
  const [statusMsg, setStatusMsg] = useState('');
  const [progress, setProgress] = useState(0);
  const [speed, setSpeed] = useState(0);
  const [chunksOk, setChunksOk] = useState(0);
  const [totalChunks, setTotalChunks] = useState(0);
  const [errorMsg, setErrorMsg] = useState('');
  const [receivedFileMeta, setReceivedFileMeta] = useState<{ name: string; size: number } | null>(null);
  const [rekeyCount, setRekeyCount] = useState(0);
  const [roomIdHash, setRoomIdHash] = useState('');
  const [receiverPassword, setReceiverPassword] = useState('');
  const [useStun, setUseStun] = useState(true);
  const [stunServer, setStunServer] = useState('stun:stun.stunprotocol.org:3478');
  const [peerjsHost, setPeerjsHost] = useState('0.peerjs.com');
  const [peerjsPort, setPeerjsPort] = useState('443');
  const [connState, setConnState] = useState<ConnState>('idle');

  const peerRef = useRef<Peer | null>(null);
  const connRef = useRef<any>(null);
  const baseAESBitsRef = useRef<ArrayBuffer | null>(null);
  const baseHMACBitsRef = useRef<ArrayBuffer | null>(null);
  const cancelRef = useRef(false);
  const fileHashRef = useRef('');
  const qrCanvasRef = useRef<HTMLCanvasElement | null>(null);
  const startedRef = useRef(false);
  const ecdhKeyRef = useRef<CryptoKeyPair | null>(null);
  const chunksRef = useRef<Map<number, ArrayBuffer>>(new Map());

  useEffect(() => {
    if (startedRef.current) return;
    const hash = window.location.hash;
    if (hash && hash.length > 1) {
      const rh = hash.slice(1);
      if (/^[0-9a-f]{32}$/i.test(rh)) {
        startedRef.current = true;
        setRoomIdHash(rh);
        setPhase('prompt');
        setStatusMsg('Introduce la clave secreta para recibir el archivo');
      }
    }
  }, []);

  useEffect(() => {
    if (phase === 'link' && linkUrl && qrCanvasRef.current) {
      drawQRToCanvas(linkUrl, qrCanvasRef.current, 5, 16);
    }
  }, [phase, linkUrl]);

  useEffect(() => {
    if (phase === 'sending' || phase === 'receiving') {
      let lastChunks = 0;
      let lastTime = Date.now();
      const iv = setInterval(() => {
        const now = Date.now();
        const elapsed = (now - lastTime) / 1000;
        if (elapsed > 0) {
          const bps = (chunksOk - lastChunks) * CHUNK_SIZE / elapsed;
          setSpeed(bps > 0 ? bps : 0);
          lastChunks = chunksOk;
          lastTime = now;
        }
      }, 1000);
      return () => clearInterval(iv);
    }
  }, [phase, chunksOk]);

  const cleanup = useCallback(() => {
    cancelRef.current = true;
    if (connRef.current) { try { connRef.current.close(); } catch {} connRef.current = null; }
    if (peerRef.current) { try { peerRef.current.destroy(); } catch {} peerRef.current = null; }
    if (baseAESBitsRef.current) { zeroBuffer(baseAESBitsRef.current); baseAESBitsRef.current = null; }
    if (baseHMACBitsRef.current) { zeroBuffer(baseHMACBitsRef.current); baseHMACBitsRef.current = null; }
    ecdhKeyRef.current = null;
    chunksRef.current = new Map();
    fileHashRef.current = '';
    setLinkUrl('');
    setPassword('');
    setReceiverPassword('');
    setConnState('idle');
  }, []);

  const DEFAULT_ICE_SERVERS = [
    { urls: 'stun:stun.l.google.com:19302' },
    { urls: ['turn:eu-0.turn.peerjs.com:3478', 'turn:us-0.turn.peerjs.com:3478'],
      username: 'peerjs', credential: 'peerjsp' }
  ];

  const getPeerOpts = useCallback(() => {
    const opts: Record<string, any> = {
      host: peerjsHost,
      port: Number(peerjsPort) || 443,
      secure: true,
      debug: 3 as any,
    };
    if (useStun && stunServer.trim()) {
      opts.config = {
        iceServers: [
          { urls: stunServer.trim() },
          ...DEFAULT_ICE_SERVERS
        ]
      };
    }
    return opts;
  }, [peerjsHost, peerjsPort, useStun, stunServer]);

  const doECDHExchange = useCallback(async (
    conn: any,
    isSender: boolean,
    remotePubKey: ArrayBuffer | null
  ): Promise<{ localPair: CryptoKeyPair; sharedSecret: ArrayBuffer }> => {
    const localPair = await generateECDHKeyPair();
    const localPubRaw = await exportPublicKey(localPair.publicKey);

    if (remotePubKey) {
      const remotePub = await importPublicKey(remotePubKey);
      const shared = await deriveECDHShared(localPair.privateKey, remotePub);
      return { localPair, sharedSecret: shared };
    }

    if (isSender) {
      conn.send(JSON.stringify({ type: 'ecdh-pub', pubKey: bufToHex(localPubRaw) }));
      return new Promise((resolve, reject) => {
        const handler = (data: any) => {
          if (typeof data === 'string') {
            try {
              const msg = JSON.parse(data);
              if (msg.type === 'ecdh-pub') {
                conn.off('data', handler);
                importPublicKey(hexToBuf(msg.pubKey)).then(async (remotePub) => {
                  const shared = await deriveECDHShared(localPair.privateKey, remotePub);
                  setRekeyCount((c) => c + 1);
                  resolve({ localPair, sharedSecret: shared });
                }).catch(reject);
              }
            } catch {}
          }
        };
        conn.on('data', handler);
      });
    } else {
      conn.send(JSON.stringify({ type: 'ecdh-pub', pubKey: bufToHex(localPubRaw) }));
      return { localPair, sharedSecret: new ArrayBuffer(0) };
    }
  }, []);

  const handleRetry = () => {
    cancelRef.current = true;
    if (connRef.current) { try { connRef.current.close(); } catch {} connRef.current = null; }
    if (peerRef.current) { try { peerRef.current.destroy(); } catch {} peerRef.current = null; }
    setErrorMsg('');
    setStatusMsg('Introduce la clave secreta para recibir el archivo');
    setPhase('prompt');
    setConnState('idle');
  };

  const startReceiver = async (pw: string, rh: string) => {
    cancelRef.current = false;
    setPhase('receiving');
    setStatusMsg('Verificando clave...');
    try {
      const derived = await deriveKeys(pw);
      if (derived.roomId.toLowerCase() !== rh.toLowerCase()) {
        setErrorMsg('La clave secreta no coincide con el enlace');
        setPhase('error');
        return;
      }
      baseAESBitsRef.current = derived.aesBits;
      baseHMACBitsRef.current = derived.hmacBits;

      setStatusMsg('Conectando al emisor...');
      setConnState('connecting');
      const peer = new Peer(getPeerOpts());
      peerRef.current = peer;

      peer.on('error', (err) => {
        setConnState('disconnected');
        setErrorMsg('Error de conexión: ' + err.message);
        setPhase('error');
      });

      peer.on('disconnected', () => {
        setConnState('disconnected');
        if (!cancelRef.current) {
          setErrorMsg('La conexión con el emisor se perdió');
          setPhase('error');
        }
      });

      let meta: { fileName: string; fileSize: number; totalChunks: number; fileHash: string } | null = null;
      let ecdhComplete = false;
      let sessionAES: CryptoKey = derived.aesKey;
      let sessionHMAC: CryptoKey = derived.hmacKey;
      let pendingAES: CryptoKey | null = null;
      let pendingHMAC: CryptoKey | null = null;
      const pendingChunks: Promise<void>[] = [];

      peer.once('open', () => {
        const conn = peer.connect(rh);
        connRef.current = conn;

        conn.on('open', () => {
          setConnState('connected');
          setStatusMsg('Conectado, intercambiando claves...');
        });

        conn.on('close', () => {
          if (cancelRef.current) return;
          setConnState('disconnected');
          if (!meta) {
            setErrorMsg('El emisor cerró la conexión antes de enviar el archivo');
          } else if (chunksRef.current.size < meta.totalChunks) {
            setErrorMsg('Conexión perdida: la transferencia se interrumpió');
          } else {
            setErrorMsg('La conexión se cerró inesperadamente');
          }
          setPhase('error');
        });

        conn.on('error', (err: any) => {
          if (cancelRef.current) return;
          setConnState('disconnected');
          setErrorMsg('Error en la transferencia: ' + (err.message || 'desconocido'));
          setPhase('error');
        });

        conn.on('data', async (data: any) => {
          if (cancelRef.current) return;

          if (typeof data === 'string') {
            try {
              const msg = JSON.parse(data);
              if (msg.type === 'ecdh-pub' && !ecdhComplete) {
                const remotePub = await importPublicKey(hexToBuf(msg.pubKey));
                const localPair = await generateECDHKeyPair();
                const shared = await deriveECDHShared(localPair.privateKey, remotePub);
                const localPubRaw = await exportPublicKey(localPair.publicKey);
                conn.send(JSON.stringify({ type: 'ecdh-pub', pubKey: bufToHex(localPubRaw) }));
                const combined = await combineKeys(
                  baseAESBitsRef.current!, baseHMACBitsRef.current!, shared
                );
                sessionAES = combined.aesKey;
                sessionHMAC = combined.hmacKey;
                ecdhComplete = true;
                setRekeyCount(1);
                setStatusMsg('Claves de sesión establecidas');
                return;
              }
              if (msg.type === 'ecdh-ratchet') {
                const remotePub = await importPublicKey(hexToBuf(msg.pubKey));
                const localPair = await generateECDHKeyPair();
                const shared = await deriveECDHShared(localPair.privateKey, remotePub);
                const localPubRaw = await exportPublicKey(localPair.publicKey);
                conn.send(JSON.stringify({ type: 'ecdh-ratchet-ack', pubKey: bufToHex(localPubRaw) }));
                const combined = await combineKeys(
                  baseAESBitsRef.current!, baseHMACBitsRef.current!, shared
                );
                pendingAES = combined.aesKey;
                pendingHMAC = combined.hmacKey;
                return;
              }
              if (msg.type === 'key-switch') {
                sessionAES = pendingAES || sessionAES;
                sessionHMAC = pendingHMAC || sessionHMAC;
                setRekeyCount((c) => c + 1);
                return;
              }
              if (msg.type === 'metadata') {
                meta = msg;
                setReceivedFileMeta({ name: msg.fileName, size: msg.fileSize });
                setTotalChunks(msg.totalChunks);
                setStatusMsg('Recibiendo archivo...');
                return;
              }
              if (msg.type === 'complete') {
                await Promise.all(pendingChunks);
                pendingChunks.length = 0;
                setStatusMsg('Verificando integridad...');
                if (!meta) { setErrorMsg('Error: metadatos no recibidos'); setPhase('error'); return; }
                const ordered: ArrayBuffer[] = [];
                for (let i = 0; i < meta.totalChunks; i++) {
                  const chunk = chunksRef.current.get(i);
                  if (!chunk) { setErrorMsg('Error: chunk faltante ' + i); setPhase('error'); return; }
                  ordered.push(chunk);
                }
                const totalLen = ordered.reduce((s, c) => s + c.byteLength, 0);
                const fullFile = new Uint8Array(totalLen);
                let off = 0;
                for (const chunk of ordered) {
                  fullFile.set(new Uint8Array(chunk), off);
                  off += chunk.byteLength;
                }
                const fHash = await hashBuffer(fullFile.buffer);
                if (fHash !== meta.fileHash) {
                  setErrorMsg('Error: verificación SHA-256 fallida');
                  setPhase('error');
                  return;
                }
                const blob = new Blob([fullFile.buffer]);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url; a.download = meta.fileName;
                document.body.appendChild(a); a.click(); document.body.removeChild(a);
                setTimeout(() => URL.revokeObjectURL(url), 5000);
                zeroBuffer(fullFile.buffer);
                chunksRef.current.clear();
                setStatusMsg('¡Archivo recibido y verificado!');
                setPhase('complete');
                setTimeout(cleanup, 1000);
              }
            } catch {}
          } else if (typeof data === 'object' && data !== null && data.type === 'chunk') {
            if (!meta) return;
            const p = (async () => {
              try {
                const buf = base64ToBuf(data.data);
                const pktView = new DataView(buf);
                const idx = pktView.getUint32(0, false);
                if (idx === 0xFFFFFFFF) return;
                const result = await decryptChunk(sessionAES, sessionHMAC, buf);
                chunksRef.current.set(result.chunkIndex, result.plaintext);
                setChunksOk((c) => c + 1);
                setProgress(Math.min(100, Math.round((chunksRef.current.size / meta!.totalChunks) * 100)));
                conn.send(JSON.stringify({ type: 'ack', chunkIndex: result.chunkIndex }));
              } catch (err: any) {
                setErrorMsg('Error al desencriptar chunk: ' + err.message);
                setPhase('error');
              }
            })();
            pendingChunks.push(p);
          }
        });
      });
    } catch (err: any) {
      setErrorMsg('Error al iniciar: ' + err.message);
      setPhase('error');
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0];
    if (f) {
      if (f.size > 4 * 1024 * 1024 * 1024) {
        setErrorMsg('El archivo es demasiado grande (máximo 4 GB)');
        setPhase('error');
        return;
      }
      setFile(f);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const f = e.dataTransfer.files?.[0];
    if (f) {
      if (f.size > 4 * 1024 * 1024 * 1024) {
        setErrorMsg('El archivo es demasiado grande (máximo 4 GB)');
        setPhase('error');
        return;
      }
      setFile(f);
    }
  };

  const handleGenerateLink = async () => {
    if (!file || !password.trim()) return;
    cancelRef.current = false;
    try {
      setStatusMsg('Derivando claves...');
      const { roomId, aesKey, hmacKey, aesBits, hmacBits } = await deriveKeys(password.trim());
      baseAESBitsRef.current = aesBits;
      baseHMACBitsRef.current = hmacBits;

      setStatusMsg('Calculando hash del archivo...');
      const buf = await file.arrayBuffer();
      const fHash = await hashBuffer(buf);
      zeroBuffer(buf);
      fileHashRef.current = fHash;

      const baseUrl = window.location.origin + window.location.pathname.replace(/\/$/, '');
      const url = baseUrl + '/#' + roomId;
      setLinkUrl(url);
      setPhase('link');
      setStatusMsg('Esperando que el receptor se conecte...');
      setConnState('connecting');

      const peer = new Peer(roomId, getPeerOpts());
      peerRef.current = peer;

      peer.on('error', (err) => {
        setConnState('disconnected');
        setErrorMsg('Error de PeerJS: ' + err.message);
        setPhase('error');
      });

      peer.on('disconnected', () => {
        setConnState('disconnected');
        if (!cancelRef.current) {
          setErrorMsg('Se perdió la conexión con el servidor de señalización');
          setPhase('error');
        }
      });

      peer.on('connection', (conn) => {
        connRef.current = conn;
        setConnState('connected');

        let sessionAES: CryptoKey = aesKey;
        let sessionHMAC: CryptoKey = hmacKey;
        let ecdhReady = false;
        let ratchetCount = 0;
        let senderECDHPair: CryptoKeyPair | null = null;

        const ecdhKeyPromise = generateECDHKeyPair();

        conn.on('open', async () => {
          setStatusMsg('Intercambiando claves ECDH...');

          senderECDHPair = await ecdhKeyPromise;
          const pubRaw = await exportPublicKey(senderECDHPair.publicKey);
          conn.send(JSON.stringify({ type: 'ecdh-pub', pubKey: bufToHex(pubRaw) }));
        });

        conn.on('close', () => {
          if (cancelRef.current) return;
          setConnState('disconnected');
          cancelRef.current = true;
          setErrorMsg(ecdhReady
            ? 'El receptor cerró la conexión durante la transferencia'
            : 'El receptor se desconectó antes de completar el intercambio de claves');
          setPhase('error');
        });

        conn.on('error', (err: any) => {
          if (cancelRef.current) return;
          setConnState('disconnected');
          setErrorMsg('Error en la transferencia: ' + (err.message || 'desconocido'));
          setPhase('error');
        });

        conn.on('data', async (data: any) => {
          if (cancelRef.current) return;

          if (typeof data === 'string') {
            try {
              const msg = JSON.parse(data);
              if (msg.type === 'ecdh-pub' && !ecdhReady) {
                const pair = senderECDHPair ?? await ecdhKeyPromise;
                const remotePub = await importPublicKey(hexToBuf(msg.pubKey));
                const shared = await deriveECDHShared(pair.privateKey, remotePub);
                const combined = await combineKeys(aesBits, hmacBits, shared);
                sessionAES = combined.aesKey;
                sessionHMAC = combined.hmacKey;
                ecdhReady = true;
                setRekeyCount(1);
                setStatusMsg('Enviando archivo...');
                sendAllChunks();
                return;
              }
              if (msg.type === 'ecdh-ratchet-ack') {
                const remotePub = await importPublicKey(hexToBuf(msg.pubKey));
                const shared = await deriveECDHShared(senderECDHPair!.privateKey, remotePub);
                const combined = await combineKeys(aesBits, hmacBits, shared);
                sessionAES = combined.aesKey;
                sessionHMAC = combined.hmacKey;
                conn.send(JSON.stringify({ type: 'key-switch' }));
                setRekeyCount((c) => c + 1);
                return;
              }
              if (msg.type === 'ack') {
                return;
              }
            } catch {}
            return;
          }
        });

        const sendAllChunks = async () => {
          const totalCh = Math.ceil(file.size / CHUNK_SIZE);
          setTotalChunks(totalCh);
          cancelRef.current = false;
          setPhase('sending');
          setStatusMsg('Enviando archivo...');

          conn.send(JSON.stringify({
            type: 'metadata',
            fileName: file.name,
            fileSize: file.size,
            totalChunks: totalCh,
            fileHash: fHash
          }));

          for (let idx = 0; idx < totalCh && !cancelRef.current; idx++) {
            if (connRef.current?.open === false) {
              setErrorMsg('Conexión perdida: el receptor se desconectó');
              setPhase('error');
              return;
            }

            if (Math.random() < ENTROPY_RATE) {
              const dummyData = crypto.getRandomValues(new Uint8Array(CHUNK_SIZE));
              const dummyPkt = await encryptChunk(sessionAES, sessionHMAC, 0xFFFFFFFF, dummyData.buffer);
              conn.send({ type: 'chunk', data: bufToBase64(dummyPkt) });
            }

            const offset = idx * CHUNK_SIZE;
            const slice = file.slice(offset, offset + CHUNK_SIZE);
            const buf = await slice.arrayBuffer();
            const packet = await encryptChunk(sessionAES, sessionHMAC, idx, buf);
            zeroBuffer(buf);
            try {
              conn.send({ type: 'chunk', data: bufToBase64(packet) });
            } catch {
              setErrorMsg('Error al enviar: la conexión se perdió');
              setPhase('error');
              return;
            }
            setChunksOk(idx + 1);
            setProgress(Math.min(100, Math.round(((idx + 1) / totalCh) * 100)));

            if (idx > 0 && idx % RATCHET_INTERVAL === 0 && !cancelRef.current) {
              setStatusMsg('Rotando claves (Double Ratchet)...');
              senderECDHPair = await generateECDHKeyPair();
              const pubRaw = await exportPublicKey(senderECDHPair.publicKey);
              conn.send(JSON.stringify({ type: 'ecdh-ratchet', pubKey: bufToHex(pubRaw) }));
              ratchetCount++;
            }
          }

          if (!cancelRef.current) {
            setStatusMsg('Transferencia completada');
            conn.send(JSON.stringify({ type: 'complete' }));
          }
        };
      });
    } catch (err: any) {
      setErrorMsg('Error: ' + err.message);
      setPhase('error');
    }
  };

  const handleReceiverSubmit = () => {
    if (!receiverPassword.trim()) return;
    startReceiver(receiverPassword.trim(), roomIdHash);
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(linkUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleCancel = () => {
    cancelRef.current = true;
    cleanup();
    setPhase('select');
    setFile(null);
    setProgress(0);
    setChunksOk(0);
    setTotalChunks(0);
    setSpeed(0);
    setStatusMsg('');
    setErrorMsg('');
    setRekeyCount(0);
    setRoomIdHash('');
    setReceiverPassword('');
    setConnState('idle');
    startedRef.current = false;
    if (window.location.hash) {
      history.replaceState(null, '', window.location.pathname + window.location.search);
    }
  };

  return (
    <div className="app">
      <div className="bg-glow" />
      <div className="bg-grid" />

      <header className="header">
        <div className="header-left">
          <div className="logo-icon">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <span className="logo-text">OXYPHER</span>
            <span className="logo-sub">Cero Nube • Cero Logs</span>
          </div>
        </div>
        <div className="header-right">
          <div className="header-badge" title={connState === 'connected' ? 'Conectado vía WebRTC' : connState === 'connecting' ? 'Conectando...' : connState === 'disconnected' ? 'Desconectado' : 'Inactivo'}>
            <div className={"header-dot " + connState} />
            {connState === 'connected' ? 'Conectado' : connState === 'connecting' ? 'Conectando...' : connState === 'disconnected' ? 'Desconectado' : 'Inactivo'}
          </div>
        </div>
      </header>

      <main className="main">

        {phase === 'error' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main"><div className="error-state">
              <p className="error-message">{errorMsg}</p>
              <div className="actions" style={{ justifyContent: 'center' }}>
                {roomIdHash && <button className="btn btn-primary" onClick={handleRetry} style={{ minWidth: 120 }}>Reintentar</button>}
                <button className="btn btn-ghost" onClick={handleCancel} style={{ minWidth: 120 }}>Volver a empezar</button>
              </div>
            </div></div>
          </div>
        )}

        {phase === 'complete' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main"><div className="success-state">
              <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'rgba(16,185,129,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 24, height: 24 }}>
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              <div className="success-title">Transferencia completada</div>
              <div className="success-sub">{statusMsg}</div>
              <div className="actions" style={{ justifyContent: 'center' }}>
                <button className="btn btn-primary" onClick={handleCancel} style={{ marginTop: 16, width: 'auto' }}>Volver a empezar</button>
              </div>
            </div></div>
          </div>
        )}

        {phase === 'prompt' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main" style={{ textAlign: 'center' }}>
              <div style={{ marginBottom: 16, fontSize: 13, color: 'var(--text2)', lineHeight: 1.6 }}>
                Has recibido un enlace para una transferencia de archivos.
                <br />Introduce la clave secreta para recibir el archivo.
              </div>
              <div className="input-group">
                <label className="input-label">Clave secreta</label>
                <input className="input-field" type="text" placeholder="Introduce la clave..." value={receiverPassword} onChange={(e) => setReceiverPassword(e.target.value)} onKeyDown={(e) => { if (e.key === 'Enter') handleReceiverSubmit(); }} />
              </div>
              <button className="btn btn-primary" disabled={!receiverPassword.trim()} onClick={handleReceiverSubmit}>
                Conectar y recibir
              </button>
              {errorMsg && <p style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>{errorMsg}</p>}
            </div>
          </div>
        )}

        {phase === 'receiving' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main" style={{ textAlign: 'center' }}>
              <div className="status-bar" style={{ justifyContent: 'center', border: 'none', background: 'transparent' }}>
                <div className="status-spinner" /><span>{statusMsg}</span>
              </div>
              {receivedFileMeta && (
                <div className="file-info" style={{ marginTop: 16, textAlign: 'left' }}>
                  <div className="file-info-icon">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16, color: '#000' }}>
                      <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="13 2 13 9 20 9" />
                    </svg>
                  </div>
                  <div className="file-info-body">
                    <div className="file-info-name">{receivedFileMeta.name}</div>
                    <div className="file-info-size">{fmtSize(receivedFileMeta.size)}</div>
                  </div>
                </div>
              )}
              {totalChunks > 0 && (
                <div className="progress-wrap">
                  <div className="progress-header"><span>{progress}%</span><span>{chunksOk}/{totalChunks}</span></div>
                  <div className="progress-bar"><div className="progress-fill" style={{ width: progress + '%' }} /></div>
                  <div className="progress-stats">
                    {speed > 0 && <span>{fmtSpeed(speed)}</span>}
                    {rekeyCount > 0 && <span>Ratchet: {rekeyCount}</span>}
                    <span>AES-256-GCM</span>
                  </div>
                </div>
              )}
              <div className="actions" style={{ justifyContent: 'center' }}>
                <button className="btn btn-danger" onClick={handleCancel}>Cancelar</button>
              </div>
            </div>
          </div>
        )}

        {phase === 'select' && (
          <div className="card">
            <div className="card-split">
              <div className="card-side">
                <div>
                  <div className="side-label">Protocolo</div>
                  <div className="side-row"><span className="side-row-label">Cifrado</span><span className="side-row-value">AES-256-GCM</span></div>
                  <div className="side-row"><span className="side-row-label">Integridad</span><span className="side-row-value">HMAC-SHA256</span></div>
                  <div className="side-row"><span className="side-row-label">Claves (KDF)</span><span className="side-row-value">HKDF-SHA256</span></div>
                  <div className="side-row"><span className="side-row-label">PFS</span><span className="side-row-value">ECDH P-256</span></div>
                </div>
                <div>
                  <div className="side-label">Conectividad</div>
                  <div className="side-row"><span className="side-row-label">Señalización</span><span className="side-row-value">PeerJS</span></div>
                  <div className="side-row"><span className="side-row-label">Transporte</span><span className="side-row-value">WebRTC</span></div>
                  <div className="side-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%' }}>
                      <span className="side-row-label">STUN</span>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
                        <input type="checkbox" checked={useStun} onChange={(e) => setUseStun(e.target.checked)} style={{ accentColor: '#10b981' }} />
                        <span className="side-row-value" style={{ fontSize: 10 }}>{useStun ? 'Activo' : 'Inactivo'}</span>
                      </label>
                    </div>
                    {useStun && <input className="input-field" style={{ fontSize: 10, padding: '4px 8px', width: '100%' }} value={stunServer} onChange={(e) => setStunServer(e.target.value)} placeholder="stun:server:port" />}
                  </div>
                  <div className="side-row" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: 4 }}>
                    <span className="side-row-label">Signal (PeerJS)</span>
                    <div style={{ display: 'flex', gap: 4, width: '100%' }}>
                      <input className="input-field" style={{ fontSize: 10, padding: '4px 8px', flex: 1 }} value={peerjsHost} onChange={(e) => setPeerjsHost(e.target.value)} placeholder="host" />
                      <input className="input-field" style={{ fontSize: 10, padding: '4px 8px', width: 55 }} value={peerjsPort} onChange={(e) => setPeerjsPort(e.target.value)} placeholder="port" />
                    </div>
                  </div>
                </div>
                <div>
                  <div className="side-label">Privacidad</div>
                  <div className="side-row"><span className="side-row-label">Persistencia</span><span className="side-row-value">Cero</span></div>
                  <div className="side-row"><span className="side-row-label">Cuentas</span><span className="side-row-value">No requiere</span></div>
                  <div className="side-row"><span className="side-row-label">Entropía</span><span className="side-row-value">10% dummy</span></div>
                </div>
              </div>
              <div className="card-main">
                <div className={"drop-zone" + (file ? " active" : "")} onDragOver={(e) => e.preventDefault()} onDrop={handleDrop}>
                  <input type="file" onChange={handleFileSelect} />
                  {file ? (
                    <div className="file-info" style={{ margin: 0, border: 'none', background: 'transparent', padding: 0 }}>
                      <div className="file-info-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16, color: '#000' }}>
                          <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="13 2 13 9 20 9" />
                        </svg>
                      </div>
                      <div className="file-info-body">
                        <div className="file-info-name">{file.name}</div>
                        <div className="file-info-size">{fmtSize(file.size)}</div>
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="drop-icon">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 40, height: 40 }}>
                          <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" y1="3" x2="12" y2="15" />
                        </svg>
                      </div>
                      <div className="drop-text"><strong>Selecciona un archivo</strong> o arrastra aquí</div>
                      <div className="drop-hint">Máximo 4 GB</div>
                    </>
                  )}
                </div>
                <div className="input-group">
                  <label className="input-label">Crea una clave secreta para este archivo</label>
                  <input className="input-field" type="text" placeholder="ej: perro-fuego, clave123, ..." value={password} onChange={(e) => setPassword(e.target.value)} />
                </div>
                <button className="btn btn-primary" disabled={!file || !password.trim()} onClick={handleGenerateLink}>
                  Generar enlace seguro
                </button>
                {errorMsg && <p style={{ color: 'var(--danger)', fontSize: 12, marginTop: 8 }}>{errorMsg}</p>}
              </div>
            </div>
          </div>
        )}

        {phase === 'link' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main" style={{ textAlign: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <div className="file-info-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16, color: '#000' }}>
                    <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="13 2 13 9 20 9" />
                  </svg>
                </div>
                <div style={{ textAlign: 'left', flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{file?.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{file ? fmtSize(file.size) : ''}</div>
                </div>
              </div>
              <div className="link-display">
                <span className="link-text">{linkUrl}</span>
                <button className="btn btn-ghost btn-sm" onClick={handleCopy}>
                  {copied ? (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  ) : (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 14, height: 14 }}>
                      <rect x="9" y="9" width="13" height="13" rx="2" ry="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                    </svg>
                  )}
                  {copied ? 'Copiado' : 'Copiar'}
                </button>
              </div>
              <div style={{ fontSize: 11, color: 'var(--text3)', marginTop: 6, lineHeight: 1.5 }}>
                Comparte este enlace con el receptor.<br />
                La clave secreta debe comunicarse por separado.
              </div>
              <div className="qr-wrap"><canvas ref={qrCanvasRef} /></div>
              <div className="status-bar" style={{ justifyContent: 'center' }}>
                <div className="status-spinner" /><span>{statusMsg}</span>
              </div>
              <div className="actions" style={{ justifyContent: 'center' }}>
                <button className="btn btn-danger" onClick={handleCancel}>Cancelar</button>
              </div>
            </div>
          </div>
        )}

        {phase === 'sending' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main" style={{ textAlign: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                <div className="file-info-icon">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 16, height: 16, color: '#000' }}>
                    <path d="M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z" /><polyline points="13 2 13 9 20 9" />
                  </svg>
                </div>
                <div style={{ textAlign: 'left', flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{file?.name}</div>
                  <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'var(--mono)' }}>{file ? fmtSize(file.size) : ''}</div>
                </div>
              </div>
              <div className="progress-wrap">
                <div className="progress-header"><span>{progress}%</span><span>{chunksOk}/{totalChunks}</span></div>
                <div className="progress-bar"><div className="progress-fill" style={{ width: progress + '%' }} /></div>
                <div className="progress-stats">
                  {speed > 0 && <span>{fmtSpeed(speed)}</span>}
                  {rekeyCount > 0 && <span>Ratchet: {rekeyCount}</span>}
                  <span>AES-256-GCM</span>
                </div>
              </div>
              <div className="status-bar" style={{ justifyContent: 'center', marginTop: 12 }}>
                <div className="status-spinner" /><span>{statusMsg}</span>
              </div>
              <div className="actions" style={{ justifyContent: 'center' }}>
                <button className="btn btn-danger" onClick={handleCancel}>Cancelar</button>
              </div>
            </div>
          </div>
        )}

        {phase === 'sent' && (
          <div className="card" style={{ maxWidth: 480 }}>
            <div className="card-main"><div className="success-state">
              <div style={{ width: 48, height: 48, borderRadius: '50%', background: 'rgba(16,185,129,0.1)', display: 'flex', alignItems: 'center', justifyContent: 'center', margin: '0 auto 12px' }}>
                <svg viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{ width: 24, height: 24 }}>
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
              <div className="success-title">Archivo enviado</div>
              <div className="success-sub">{statusMsg}</div>
              <button className="btn btn-primary" onClick={handleCancel} style={{ marginTop: 16, width: 'auto' }}>Enviar otro archivo</button>
            </div></div>
          </div>
        )}

        <div style={{ fontSize: 10, color: 'var(--text3)', marginTop: 24, textAlign: 'center', fontFamily: 'var(--mono)' }}>
          Sin servidores • Sin persistencia • Encriptado extremo a extremo
        </div>
      </main>
    </div>
  );
}
