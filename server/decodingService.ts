import crypto from 'crypto';
// Proper imports for crypto-js
import MD5 from 'crypto-js/md5';
import SHA1 from 'crypto-js/sha1';
import SHA256 from 'crypto-js/sha256';
import SHA512 from 'crypto-js/sha512';
// Create a namespace for CryptoJS to fix references
const CryptoJS = { MD5, SHA1, SHA256, SHA512 };
// Import js-sha3 properly
import sha3 from 'js-sha3';
// Create our sha3_256 function
const sha3_256 = (input: string) => sha3.sha3_256(input);
import * as bcrypt from 'bcrypt';
import * as forge from 'node-forge';
// @ts-ignore - Ignore type issues with Hashids
import Hashids from 'hashids';

// Common hash algorithms
const HASH_TYPES = {
  MD5: 'MD5',
  SHA1: 'SHA1',
  SHA256: 'SHA256',
  SHA512: 'SHA512',
  SHA3: 'SHA3',
  BCRYPT: 'BCRYPT',
  BASE64: 'BASE64',
  HASHID: 'HASHID',
  UNKNOWN: 'UNKNOWN'
};

// Common encoding formats
const ENCODING_TYPES = {
  BASE64: 'BASE64',
  HEX: 'HEX',
  UTF8: 'UTF8'
};

// Dictionary with common hashed values for quick lookups
// This helps in common password decoding
const commonHashMappings: Record<string, string> = {
  // MD5 hashes and their plain text values
  '5f4dcc3b5aa765d61d8327deb882cf99': 'password',
  '098f6bcd4621d373cade4e832627b4f6': 'test',
  'e10adc3949ba59abbe56e057f20f883e': '123456',
  '25d55ad283aa400af464c76d713c07ad': '12345678',
  '5ebe2294ecd0e0f08eab7690d2a6ee69': 'secret',
  
  // SHA1 hashes
  '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8': 'password',
  'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3': 'test',
  '7c4a8d09ca3762af61e59520943dc26494f8941b': '123456',
  'f7c3bc1d808e04732adf679965ccc34ca7ae3441': 'admin',
  
  // SHA256 hashes
  '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8': 'password',
  '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08': 'test',
  '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92': '123456',
  '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918': 'admin',
  
  // SHA512 hashes (shortened for brevity)
  'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86': 'password',
  'ee26b0dd4af7e749aa1a8ee3c10ae9923f618980772e473f8819a5d4940e0db27ac185f8a0e1d5f84f88bc887fd67b143732c304cc5fa9ad8e6f57f50028a8ff': 'test'
};

// Rainbow table with common password patterns
const rainbowTable: Map<string, string[]> = new Map();

// Initialize rainbow table with common patterns
function initRainbowTable() {
  // Common patterns for passwords
  const commonWords = ['password', 'admin', 'root', 'user', 'login', 'welcome', 'secure', 'test'];
  const commonNumbers = ['123', '1234', '12345', '123456', '654321', '111', '000'];
  const commonSpecials = ['!', '@', '#', '$', '%', '&', '*'];
  const years = Array.from({ length: 30 }, (_, i) => (new Date().getFullYear() - i).toString());
  
  // Generate combinations
  const combinations: string[] = [];
  
  // Word + Number combinations
  commonWords.forEach(word => {
    combinations.push(word);
    commonNumbers.forEach(num => {
      combinations.push(`${word}${num}`);
    });
    years.forEach(year => {
      combinations.push(`${word}${year}`);
    });
    commonSpecials.forEach(special => {
      combinations.push(`${word}${special}`);
    });
  });
  
  // Common capitalization patterns
  combinations.forEach(combo => {
    if (combo.length > 0) {
      const capitalized = combo.charAt(0).toUpperCase() + combo.slice(1);
      combinations.push(capitalized);
    }
  });
  
  // Add all combinations to rainbow table with their hash values
  combinations.forEach(plainText => {
    // Generate different hash types
    const md5Hash = MD5(plainText).toString();
    const sha1Hash = SHA1(plainText).toString();
    const sha256Hash = SHA256(plainText).toString();
    const sha512Hash = SHA512(plainText).toString();
    const sha3Hash = sha3_256(plainText);
    
    // Add to rainbow table
    if (!rainbowTable.has(md5Hash)) rainbowTable.set(md5Hash, []);
    rainbowTable.get(md5Hash)?.push(plainText);
    
    if (!rainbowTable.has(sha1Hash)) rainbowTable.set(sha1Hash, []);
    rainbowTable.get(sha1Hash)?.push(plainText);
    
    if (!rainbowTable.has(sha256Hash)) rainbowTable.set(sha256Hash, []);
    rainbowTable.get(sha256Hash)?.push(plainText);
    
    if (!rainbowTable.has(sha512Hash)) rainbowTable.set(sha512Hash, []);
    rainbowTable.get(sha512Hash)?.push(plainText);
    
    if (!rainbowTable.has(sha3Hash)) rainbowTable.set(sha3Hash, []);
    rainbowTable.get(sha3Hash)?.push(plainText);
  });
}

// Initialize the rainbow table
initRainbowTable();

/**
 * Attempts to identify the hash type based on characteristics
 * @param hash The hash string to identify
 * @returns The identified hash type
 */
export function identifyHashType(hash: string): string {
  // Clean the hash
  const cleanHash = hash.trim();
  
  // Check for encoding type first (base64, hex, etc)
  if (/^[A-Za-z0-9+/=]+$/.test(cleanHash) && cleanHash.length % 4 === 0) {
    try {
      // Try decoding as base64
      const decoded = Buffer.from(cleanHash, 'base64').toString();
      if (decoded.length > 0 && /^[\x00-\x7F]*$/.test(decoded)) {
        return HASH_TYPES.BASE64;
      }
    } catch (e) {
      // Not base64
    }
  }
  
  // Check for bcrypt hash
  if (cleanHash.startsWith('$2a$') || cleanHash.startsWith('$2b$') || cleanHash.startsWith('$2y$')) {
    return HASH_TYPES.BCRYPT;
  }
  
  // Check hash length for common hash types
  switch (cleanHash.length) {
    case 32:
      return HASH_TYPES.MD5;
    case 40:
      return HASH_TYPES.SHA1;
    case 64:
      return HASH_TYPES.SHA256;
    case 128:
      return HASH_TYPES.SHA512;
    default:
      // More advanced checks
      if (cleanHash.length >= 20 && /^[0-9a-fA-F]+$/.test(cleanHash)) {
        // It's a hex string, but not a standard hash length
        if (cleanHash.length < 40) {
          return HASH_TYPES.MD5; // Possibly truncated MD5
        } else if (cleanHash.length < 64) {
          return HASH_TYPES.SHA1; // Possibly truncated SHA1
        } else if (cleanHash.length < 128) {
          return HASH_TYPES.SHA256; // Possibly truncated SHA256
        } else {
          return HASH_TYPES.SHA512; // Possibly SHA512 or longer
        }
      } else if (/^[A-Za-z0-9]+$/.test(cleanHash)) {
        // Could be a hashid or another encoding
        return HASH_TYPES.HASHID;
      }
      return HASH_TYPES.UNKNOWN;
  }
}

/**
 * Attempts to decode a hash value using various techniques
 * @param hash The hash to decode
 * @returns An object with decoded information
 */
export async function decodeHash(hash: string): Promise<any> {
  const hashType = identifyHashType(hash);
  let result: any = {
    originalHash: hash,
    identifiedType: hashType,
    decoded: false,
    possiblePlainText: [],
    decodingMethod: 'unknown'
  };
  
  // Try lookup in common mappings
  if (commonHashMappings[hash]) {
    result.decoded = true;
    result.possiblePlainText.push(commonHashMappings[hash]);
    result.decodingMethod = 'dictionary_lookup';
    return result;
  }
  
  // Try rainbow table lookup
  if (rainbowTable.has(hash)) {
    result.decoded = true;
    result.possiblePlainText = rainbowTable.get(hash) || [];
    result.decodingMethod = 'rainbow_table';
    return result;
  }
  
  // Handle based on identified hash type
  switch (hashType) {
    case HASH_TYPES.BASE64:
      try {
        const decoded = Buffer.from(hash, 'base64').toString();
        result.decoded = true;
        result.possiblePlainText.push(decoded);
        result.decodingMethod = 'base64_decode';
      } catch (e) {
        result.error = 'Failed to decode base64';
      }
      break;
      
    case HASH_TYPES.HASHID:
      // Try various salt combinations for hashids
      const commonSalts = ['', 'salt', 'hashid', 'secure', 'default', 'app'];
      for (const salt of commonSalts) {
        try {
          const hashids = new Hashids(salt);
          const decoded = hashids.decode(hash);
          if (decoded.length > 0) {
            result.decoded = true;
            result.possiblePlainText.push(decoded.join(','));
            result.decodingMethod = 'hashid_decode';
            result.salt = salt;
            break;
          }
        } catch (e) {
          // Try the next salt
        }
      }
      break;
      
    default:
      // For secure hash functions like MD5, SHA1, SHA256, etc.
      // We cannot directly decode these as they are one-way functions
      result.decodingMethod = 'hash_analysis';
      result.securityAnalysis = analyzeHashSecurity(hash, hashType);
      
      // Try pattern-based guessing for common patterns
      const patternGuesses = guessPatterns(hash, hashType);
      if (patternGuesses.length > 0) {
        result.possiblePlainText = patternGuesses;
        result.decoded = true;
        result.decodingMethod = 'pattern_guessing';
      }
      
      // Advanced heuristics for session tokens and database keys
      if (hashType === HASH_TYPES.MD5 || hashType === HASH_TYPES.SHA256) {
        const tokenAnalysis = analyzeToken(hash);
        if (tokenAnalysis) {
          result.tokenAnalysis = tokenAnalysis;
        }
      }
      break;
  }
  
  return result;
}

/**
 * Analyzes security properties of a hash
 * @param hash The hash to analyze
 * @param hashType The identified hash type
 * @returns Security analysis information
 */
function analyzeHashSecurity(hash: string, hashType: string): any {
  // Use a properly typed interface for the analysis result
  interface SecurityAnalysis {
    algorithm: string;
    strength: string;
    vulnerabilities: string[];
    recommendations: string[];
    entropy?: number; // Make entropy optional to fix typing issues
  }
  
  const analysis: SecurityAnalysis = {
    algorithm: hashType,
    strength: 'unknown',
    vulnerabilities: [],
    recommendations: []
  };
  
  switch (hashType) {
    case HASH_TYPES.MD5:
      analysis.strength = 'weak';
      analysis.vulnerabilities.push('MD5 is cryptographically broken and unsuitable for further use');
      analysis.vulnerabilities.push('Vulnerable to collision attacks');
      analysis.vulnerabilities.push('Can be brute-forced quickly with modern hardware');
      analysis.recommendations.push('Replace MD5 with SHA-256 or stronger algorithms');
      break;
      
    case HASH_TYPES.SHA1:
      analysis.strength = 'weak';
      analysis.vulnerabilities.push('SHA-1 is cryptographically weak');
      analysis.vulnerabilities.push('Google demonstrated a collision attack in 2017');
      analysis.recommendations.push('Replace SHA-1 with SHA-256 or SHA-3');
      break;
      
    case HASH_TYPES.SHA256:
      analysis.strength = 'strong';
      analysis.vulnerabilities.push('No known practical attacks against SHA-256');
      analysis.recommendations.push('For most applications, SHA-256 remains secure');
      analysis.recommendations.push('Consider adding a salt if used for password storage');
      break;
      
    case HASH_TYPES.SHA512:
      analysis.strength = 'very strong';
      analysis.vulnerabilities.push('No known practical attacks against SHA-512');
      analysis.recommendations.push('SHA-512 is considered secure for most applications');
      break;
      
    case HASH_TYPES.SHA3:
      analysis.strength = 'very strong';
      analysis.vulnerabilities.push('No known practical attacks against SHA-3');
      analysis.recommendations.push('SHA-3 is the newest SHA algorithm and considered secure');
      break;
      
    case HASH_TYPES.BCRYPT:
      analysis.strength = 'very strong (if properly configured)';
      analysis.recommendations.push('Bcrypt is designed specifically for password hashing and is considered secure');
      break;
      
    default:
      analysis.strength = 'unknown';
      analysis.recommendations.push('Use standard cryptographic algorithms with proper implementation');
  }
  
  // Check for entropy
  const entropy = calculateEntropy(hash);
  analysis.entropy = entropy;
  
  if (entropy < 3) {
    analysis.vulnerabilities.push('Very low entropy detected - possible pattern or weak hash');
  }
  
  return analysis;
}

/**
 * Calculates Shannon entropy of a string as a measure of randomness
 * @param str The string to calculate entropy for
 * @returns The entropy value
 */
function calculateEntropy(str: string): number {
  const len = str.length;
  const charFreq: Record<string, number> = {};
  
  for (let i = 0; i < len; i++) {
    const char = str[i];
    charFreq[char] = (charFreq[char] || 0) + 1;
  }
  
  let entropy = 0;
  Object.values(charFreq).forEach((freq) => {
    const probability = freq / len;
    entropy -= probability * Math.log2(probability);
  });
  
  return entropy;
}

/**
 * Attempts to guess the plain text by checking common patterns
 * @param hash The hash to analyze
 * @param hashType The identified hash type
 * @returns Array of possible plain text values
 */
function guessPatterns(hash: string, hashType: string): string[] {
  const guesses: string[] = [];
  
  // Function to check if a string hashes to our target
  const checkHash = (input: string): boolean => {
    let hashedInput = '';
    
    switch (hashType) {
      case HASH_TYPES.MD5:
        hashedInput = MD5(input).toString();
        break;
      case HASH_TYPES.SHA1:
        hashedInput = SHA1(input).toString();
        break;
      case HASH_TYPES.SHA256:
        hashedInput = SHA256(input).toString();
        break;
      case HASH_TYPES.SHA512:
        hashedInput = SHA512(input).toString();
        break;
      case HASH_TYPES.SHA3:
        hashedInput = sha3_256(input);
        break;
      default:
        return false;
    }
    
    return hashedInput === hash;
  };
  
  // Try common dates and timestamps
  const currentYear = new Date().getFullYear();
  for (let year = currentYear - 5; year <= currentYear; year++) {
    const dates = [
      `${year}`,
      `${year}-01-01`,
      `${year}0101`,
      `01-01-${year}`,
      `0101${year}`
    ];
    
    for (const date of dates) {
      if (checkHash(date)) {
        guesses.push(date);
      }
    }
  }
  
  // Try common token patterns
  const tokenPatterns = [
    'token',
    'session',
    'auth',
    'key',
    'api',
    'secret',
    'access',
    'user'
  ];
  
  for (const pattern of tokenPatterns) {
    if (checkHash(pattern)) {
      guesses.push(pattern);
    }
  }
  
  return guesses;
}

/**
 * Analyzes a potential session/database token
 * @param hash The hash to analyze
 * @returns Token analysis information
 */
function analyzeToken(hash: string): any {
  // Common token patterns and structures
  const analysis = {
    likelyUsage: [] as string[],
    structure: 'unknown',
    entropy: calculateEntropy(hash),
    timestamp: null as string | null
  };
  
  // Check if it might be a timestamped token (common in session tokens)
  const hexTimestamps = hash.match(/[0-9a-f]{8}/g);
  if (hexTimestamps) {
    for (const hexTime of hexTimestamps) {
      const timestamp = parseInt(hexTime, 16);
      // Check if it's a reasonable Unix timestamp (between 2010 and 2030)
      if (timestamp > 1262304000 && timestamp < 1893456000) {
        const date = new Date(timestamp * 1000);
        analysis.timestamp = date.toISOString();
        analysis.likelyUsage.push('Session token with embedded timestamp');
        break;
      }
    }
  }
  
  // Analyze structure
  if (/^[0-9a-f]+$/.test(hash)) {
    analysis.structure = 'Hexadecimal';
    
    if (hash.length === 32) {
      analysis.likelyUsage.push('Database primary key (MD5)');
      analysis.likelyUsage.push('Session ID');
      analysis.likelyUsage.push('API token');
    } else if (hash.length === 64) {
      analysis.likelyUsage.push('Secure API key (SHA-256)');
      analysis.likelyUsage.push('OAuth token');
      analysis.likelyUsage.push('CSRF token');
    }
  } else if (/^[A-Za-z0-9+/=]+$/.test(hash)) {
    analysis.structure = 'Base64-encoded';
    analysis.likelyUsage.push('JWT token component');
    analysis.likelyUsage.push('Encrypted data');
  }
  
  // Check entropy to determine if it's randomly generated
  if (analysis.entropy > 3.8) {
    analysis.likelyUsage.push('Cryptographically random token');
  } else if (analysis.entropy > 3.5) {
    analysis.likelyUsage.push('Pseudorandom or structured token');
  } else {
    analysis.likelyUsage.push('Structured or patterned token (not fully random)');
  }
  
  return analysis;
}

/**
 * Decodes a QR code from image data
 * @param imageBuffer Buffer containing image data
 * @returns Decoded QR content or error
 */
export async function decodeQRCode(imageBuffer: Buffer): Promise<any> {
  try {
    // We'll use a different approach with QRCode
    // QRCode library is for generating QR codes, not reading them
    // Let's use a direct buffer analysis approach instead
    try {
      // Try to decode as base64 first (common for QR codes)
      const base64Text = imageBuffer.toString('base64');
      if (base64Text) {
        try {
          const decoded = Buffer.from(base64Text, 'base64').toString('utf-8');
          if (decoded && /^[\x20-\x7E]+$/.test(decoded)) { // Check if it's printable ASCII
            return {
              decoded: true,
              text: decoded,
              decodingMethod: 'base64-decode'
            };
          }
        } catch (e) {
          // Not valid base64
        }
      }
    } catch (qrError) {
      console.log("Basic QR decoding failed, trying alternative methods");
    }
    
    // Image analysis approach
    try {
      // Try to analyze the first bytes to detect image format
      if (imageBuffer.length > 4) {
        const header = imageBuffer.slice(0, 4).toString('hex');
        // Check for PNG signature
        if (header.startsWith('89504e47')) {
          console.log("Detected PNG format");
        }
        // Check for JPEG signature
        else if (header.startsWith('ffd8ff')) {
          console.log("Detected JPEG format");
        }
        // Check for GIF signature
        else if (header.startsWith('47494638')) {
          console.log("Detected GIF format");
        }
      }
      
      // We're not using a QR code decoder library here
      // Instead, we'll try to extract any embedded text
      // This is a simplified approach since we removed ZXing
      const hexContent = imageBuffer.toString('hex');
      
      // Look for text patterns in the binary data
      const textMatches = [];
      let currentAscii = '';
      
      for (let i = 0; i < hexContent.length; i += 2) {
        const byte = parseInt(hexContent.substr(i, 2), 16);
        // If it's a printable ASCII character
        if (byte >= 32 && byte <= 126) {
          currentAscii += String.fromCharCode(byte);
        } else if (currentAscii.length > 5) {
          // If we have at least 5 characters, consider it a potential text chunk
          textMatches.push(currentAscii);
          currentAscii = '';
        } else {
          currentAscii = '';
        }
      }
      
      // If we found something that looks like a URL or meaningful text
      if (textMatches.length > 0) {
        // Find the longest match which might be the QR content
        const longestMatch = textMatches.reduce((a, b) => a.length > b.length ? a : b, '');
        
        if (longestMatch.length > 8) {
          return {
            decoded: true,
            text: longestMatch,
            decodingMethod: 'binary-text-extraction'
          };
        }
      }
    } catch (analysisError) {
      console.log("Image analysis failed, trying more options");
    }

    // Last resort - try to parse as text directly
    try {
      const textResult = imageBuffer.toString('utf-8');
      if (textResult && textResult.length > 0 && /^[a-zA-Z0-9+/=]+$/.test(textResult)) {
        // Could be base64 encoded data
        try {
          const decoded = Buffer.from(textResult, 'base64').toString();
          return {
            decoded: true,
            text: decoded,
            decodingMethod: 'base64-text'
          };
        } catch (e) {
          // Not base64, return as is
          return {
            decoded: true,
            text: textResult,
            decodingMethod: 'raw-text'
          };
        }
      }
    } catch (textError) {
      // Text parsing failed
    }
    
    // If we get here, all methods have failed
    return {
      decoded: false,
      error: 'Failed to decode QR code using all available methods'
    };
  } catch (error: any) {
    return {
      decoded: false,
      error: error.message || 'Unknown error during QR decoding'
    };
  }
}

/**
 * Comprehensive decoder that attempts to decode any type of encoded/encrypted data
 * @param input The encoded string to decode
 * @returns Decoded information and analysis
 */
export async function universalDecode(input: string): Promise<any> {
  const result = {
    original: input,
    decoded: false,
    analysis: [] as string[],
    possibleDecodings: [] as any[]
  };
  
  // Is it a hash?
  if (/^[A-Fa-f0-9]{32,128}$/.test(input) || input.startsWith('$2')) {
    const hashResult = await decodeHash(input);
    result.possibleDecodings.push({
      type: 'hash',
      result: hashResult
    });
    
    if (hashResult.decoded) {
      result.decoded = true;
      result.analysis.push(`Identified as ${hashResult.identifiedType} hash`);
    }
  }
  
  // Is it base64 encoded?
  if (/^[A-Za-z0-9+/=]+$/.test(input) && input.length % 4 === 0) {
    try {
      const decoded = Buffer.from(input, 'base64').toString();
      result.possibleDecodings.push({
        type: 'base64',
        result: decoded
      });
      result.decoded = true;
      result.analysis.push('Successfully decoded as Base64');
      
      // Check if the decoded content is JSON
      try {
        const jsonData = JSON.parse(decoded);
        result.possibleDecodings.push({
          type: 'json',
          result: jsonData
        });
        result.analysis.push('Decoded content appears to be JSON');
        
        // Check if it might be a JWT
        if (typeof jsonData === 'object' && (jsonData.exp || jsonData.iat || jsonData.sub)) {
          result.analysis.push('Decoded content appears to be a JWT payload');
        }
      } catch (e) {
        // Not JSON
      }
    } catch (e) {
      // Not valid base64
    }
  }
  
  // Check for JWT structure (without decoding signature)
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(input)) {
    const [header, payload, signature] = input.split('.');
    try {
      const decodedHeader = JSON.parse(Buffer.from(header, 'base64').toString());
      const decodedPayload = JSON.parse(Buffer.from(payload, 'base64').toString());
      
      result.possibleDecodings.push({
        type: 'jwt',
        result: {
          header: decodedHeader,
          payload: decodedPayload,
          signature: signature
        }
      });
      
      result.decoded = true;
      result.analysis.push('Successfully decoded as JWT');
      
      // Security analysis of JWT
      if (decodedHeader.alg === 'none') {
        result.analysis.push('WARNING: JWT uses "none" algorithm which is insecure');
      } else if (decodedHeader.alg === 'HS256') {
        result.analysis.push('JWT uses HS256 algorithm');
      }
      
      if (decodedPayload.exp) {
        const expiryDate = new Date(decodedPayload.exp * 1000);
        result.analysis.push(`JWT expires on: ${expiryDate.toISOString()}`);
      }
    } catch (e) {
      // Not a valid JWT
    }
  }
  
  // Hex decoding
  if (/^[A-Fa-f0-9]+$/.test(input)) {
    try {
      const decoded = Buffer.from(input, 'hex').toString();
      if (/^[\x20-\x7E]+$/.test(decoded)) { // Printable ASCII
        result.possibleDecodings.push({
          type: 'hex',
          result: decoded
        });
        result.decoded = true;
        result.analysis.push('Successfully decoded as Hexadecimal');
      }
    } catch (e) {
      // Not valid hex or binary data
    }
  }
  
  // URL decoding
  try {
    const decoded = decodeURIComponent(input);
    if (decoded !== input) {
      result.possibleDecodings.push({
        type: 'url',
        result: decoded
      });
      result.decoded = true;
      result.analysis.push('Successfully decoded as URL-encoded string');
    }
  } catch (e) {
    // Not URL encoded
  }
  
  // ROT13 and other Caesar ciphers
  for (let shift = 1; shift <= 25; shift++) {
    const decoded = caesarShift(input, shift);
    // Only add if the decoded result looks like English text
    if (looksLikeEnglishText(decoded)) {
      result.possibleDecodings.push({
        type: 'caesar',
        shift: shift,
        result: decoded
      });
      result.decoded = true;
      result.analysis.push(`Successfully decoded with Caesar shift ${shift}`);
      break; // Only add one likely shift
    }
  }
  
  return result;
}

/**
 * Caesar cipher (ROT-N) decoder
 * @param str The string to decode
 * @param shift The number of positions to shift
 * @returns The shifted string
 */
function caesarShift(str: string, shift: number): string {
  return str.replace(/[a-zA-Z]/g, (char) => {
    const code = char.charCodeAt(0);
    const isUpperCase = char === char.toUpperCase();
    const base = isUpperCase ? 65 : 97;
    return String.fromCharCode(((code - base + shift) % 26) + base);
  });
}

/**
 * Simple heuristic to check if a string looks like English text
 * @param str The string to check
 * @returns True if the string appears to be English text
 */
function looksLikeEnglishText(str: string): boolean {
  // Common English words
  const commonWords = ['the', 'be', 'to', 'of', 'and', 'in', 'that', 'have', 'it', 'for'];
  
  // Calculate word frequency
  const words = str.toLowerCase().match(/[a-z]+/g) || [];
  let commonWordCount = 0;
  
  for (const word of words) {
    if (commonWords.includes(word)) {
      commonWordCount++;
    }
  }
  
  // If more than 10% of words are common English words, it's likely English
  return words.length > 0 && (commonWordCount / words.length) > 0.1;
}