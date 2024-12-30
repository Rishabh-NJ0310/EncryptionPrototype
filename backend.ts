// Backend (Node.js/TypeScript)
import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

interface EncryptionKey {
key: Buffer;
iv: Buffer;
}

interface SessionData {
sessionToken: string;
encryptionKey: EncryptionKey;
expiresAt: Date;
}

class EncryptionService {
private static readonly ALGORITHM = 'aes-256-gcm';
private static readonly KEY_LENGTH = 32;
private static readonly IV_LENGTH = 16;
private sessions: Map<string, SessionData> = new Map();

generateEncryptionKey(): EncryptionKey {
    return {
    key: crypto.randomBytes(this.KEY_LENGTH),
    iv: crypto.randomBytes(this.IV_LENGTH)
    };
}

encrypt(data: string, key: EncryptionKey): string {
    const cipher = crypto.createCipheriv(
    EncryptionService.ALGORITHM, 
    key.key, 
    key.iv
    );
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    
    return `${encrypted}:${authTag.toString('hex')}:${key.iv.toString('hex')}`;
    }

    decrypt(encryptedData: string, key: EncryptionKey): string {
    const [encrypted, authTag, iv] = encryptedData.split(':');
    
    const decipher = crypto.createDecipheriv(
        EncryptionService.ALGORITHM,
        key.key,
        Buffer.from(iv, 'hex')
    );
    
    decipher.setAuthTag(Buffer.from(authTag, 'hex'));
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
    }

    createSession(userId: string): SessionData {
    const sessionToken = uuidv4();
    const encryptionKey = this.generateEncryptionKey();
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const sessionData = { sessionToken, encryptionKey, expiresAt };
    this.sessions.set(sessionToken, sessionData);

    return sessionData;
    }

    validateSession(sessionToken: string): EncryptionKey | null {
    const session = this.sessions.get(sessionToken);
    if (!session || session.expiresAt < new Date()) {
        return null;
    }
    return session.encryptionKey;
    }
}

export default EncryptionService;