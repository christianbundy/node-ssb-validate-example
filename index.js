const sodium = require("sodium-native");

module.exports = (input, hmacKey = null) =>
  [
    ({ hash }) => hash === "sha256",

    // Serialized messages contain fewer than 8 kibibytes.
    (input) =>
      Buffer.from(JSON.stringify(input, null, 2), "latin1").byteLength <= 8192,

    // Object properties are in the correct order.
    // IMPORTANT: Apparently `author` and `sequence` can swap places.
    (input) => {
      const {
        previous,
        author,
        sequence,
        timestamp,
        hash,
        content,
        signature,
      } = input;

      const copyAuthorFirst = {
        previous,
        author,
        sequence,
        timestamp,
        hash,
        content,
        signature,
      };

      const copySequenceFirst = {
        previous,
        sequence,
        author,
        timestamp,
        hash,
        content,
        signature,
      };
      const sameWithAuthorFirst =
        JSON.stringify(input) === JSON.stringify(copyAuthorFirst);
      const sameWithSequenceFirst =
        JSON.stringify(input) === JSON.stringify(copySequenceFirst);
      return sameWithAuthorFirst || sameWithSequenceFirst;
    },

    // Make sure that `content` is either an object with a valid type, or a
    // boxed string with valid base64.
    ({ content }) => {
      switch (typeof content) {
        case "object":
          return (
            content !== null &&
            Array.isArray(content) === false &&
            typeof content.type === "string" &&
            content.type.length >= 3 &&
            content.type.length <= 52
          );
        case "string": {
          const parts = content.split(".box");
          const base64 = parts[0];
          const base64AndBack = Buffer.from(base64, "base64").toString(
            "base64"
          );
          return base64 === base64AndBack;
        }
        default:
          return false;
      }
    },

    // Signature must be valid.
    (input, hmacKey) => {
      const signature = input.signature;

      const copy = JSON.parse(JSON.stringify(input));
      delete copy.signature;

      const message = JSON.stringify(copy, null, 2);
      const publicKeyBytes = Buffer.from(input.author.slice(1, 45), "base64");
      const signatureBytes = Buffer.from(signature.split(".")[0], "base64");

      const out = Buffer.alloc(sodium.crypto_auth_BYTES);

      if (hmacKey !== null) {
        const key = Buffer.from(hmacKey, "base64");
        sodium.crypto_auth(out, Buffer.from(message), key);
      }

      const payload = hmacKey === null ? Buffer.from(message) : out;

      return sodium.crypto_sign_verify_detached(
        signatureBytes,
        payload,
        publicKeyBytes
      );
    },
  ].every((fn) => fn(input, hmacKey));
