const sodium = require("sodium-native");

module.exports = (message, hmacKey = null, state = { id: null, sequence: 0 }) =>
  typeof message === "object" &&
  message !== null &&
  Array.isArray(message) === false &&
  // Usually when we encode a message we use Latin-1.
  Buffer.from(JSON.stringify(message, null, 2), "latin1").byteLength <= 8192 &&
  Object.keys(message).length === 7 &&
  Object.entries(message).every(([key, value], index) => {
    switch (key) {
      case "previous":
        return index === 0 && value === state.id;
      case "author":
        return index === 1 || index === 2;
      case "sequence":
        return index === 1 || (index === 2 && value === state.sequence + 1);
      case "timestamp":
        return index === 3 && typeof value === "number";
      case "hash":
        return index === 4 && value === "sha256";
      case "content":
        if (index !== 5) {
          return false;
        }
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
      case "signature": {
        const suffix = ".sig.ed25519";

        if (
          index !== 6 ||
          typeof value !== "string" ||
          value.endsWith(suffix) === false
        ) {
          return false;
        }

        const unsignedMessage = Object.fromEntries(
          Object.entries(message).filter(([key]) => key !== "signature")
        );

        // When checking signatures, we need to use UTF-8.
        const unsignedUtf8 = Buffer.from(
          JSON.stringify(unsignedMessage, null, 2),
          "utf8"
        );

        if (typeof message.author !== "string") {
          return false;
        }

        const authorSuffix = ".ed25519";

        if (message.author.endsWith(authorSuffix) === false) {
          return false;
        }

        const publicKeyChars = message.author.slice(
          1,
          message.author.length - authorSuffix.length
        );
        const publicKeyBytes = Buffer.from(publicKeyChars, "base64");

        // Canonical check
        if (publicKeyChars !== publicKeyBytes.toString("base64")) {
          return false;
        }

        if (publicKeyBytes.length !== sodium.crypto_sign_PUBLICKEYBYTES) {
          return false;
        }

        const signatureChars = value.slice(0, value.length - suffix.length);
        const signatureBytes = Buffer.from(signatureChars, "base64");

        if (
          signatureBytes.length !== sodium.crypto_sign_BYTES ||
          signatureBytes.toString("base64") !== signatureChars
        ) {
          return false;
        }

        const out = Buffer.alloc(sodium.crypto_auth_BYTES);

        if (hmacKey !== null && typeof hmacKey === "string") {
          const key = Buffer.from(hmacKey, "base64");
          if (key.length !== sodium.crypto_auth_KEYBYTES) {
            return false;
          }
          sodium.crypto_auth(out, unsignedUtf8, key);
        }

        const payload = hmacKey === null ? unsignedUtf8 : out;

        return sodium.crypto_sign_verify_detached(
          signatureBytes,
          payload,
          publicKeyBytes
        );
      }
    }
  });
