const sodium = require("sodium-native");

module.exports = (message, hmacKey = null) =>
  // Usually when we encode a message we use Latin-1.
  Buffer.from(JSON.stringify(message, null, 2), "latin1").byteLength <= 8192 &&
  Object.entries(message).every(([key, value], index) => {
    switch (key) {
      case "previous":
        return index === 0;
      case "author":
        return index === 1 || index === 2;
      case "sequence":
        return index === 1 || (index === 2 && Number.isInteger(value));
      case "timestamp":
        return index === 3 && typeof value === "number";
      case "hash":
        return index === 4 && value === "sha256";
      case "content":
        if (index === 5) {
          switch (typeof value) {
            case "object":
              return (
                value !== null &&
                Array.isArray(value) === false &&
                typeof value.type === "string" &&
                value.type.length >= 3 &&
                value.type.length <= 52
              );
            case "string": {
              const parts = value.split(".box");
              const base64 = parts[0];
              const base64AndBack = Buffer.from(base64, "base64").toString(
                "base64"
              );
              return base64 === base64AndBack;
            }
            default:
              return false;
          }
        } else {
          return false;
        }
      case "signature": {
        const copy = JSON.parse(JSON.stringify(message));
        delete copy.signature;

        // When checking signatures, we need to use UTF-8.
        const copyUtf8 = Buffer.from(JSON.stringify(copy, null, 2), "utf8");

        const publicKeyBytes = Buffer.from(copy.author.slice(1, 45), "base64");
        const signatureBytes = Buffer.from(value.split(".")[0], "base64");

        const out = Buffer.alloc(sodium.crypto_auth_BYTES);

        if (hmacKey !== null) {
          const key = Buffer.from(hmacKey, "base64");
          sodium.crypto_auth(out, copyUtf8, key);
        }

        const payload = hmacKey === null ? copyUtf8 : out;

        return sodium.crypto_sign_verify_detached(
          signatureBytes,
          payload,
          publicKeyBytes
        );
      }
    }
  });
