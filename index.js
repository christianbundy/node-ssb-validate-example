const sodium = require("sodium-native");

const checks = [
  ({ hash }) => hash === "sha256",

  // Messages should be less than
  // MESSAGES ARE NOT VALIDATED BY BYTE LENGTH, BUT UTF-8 LENGTH!!!!
  (input) =>
    Buffer.from(JSON.stringify(input, null, 2), "latin1").byteLength <= 8192,

  // Correct order
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

    // AUTHOR AND SEQUENCE MAY BE SWAPPED!!!!!
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
        const base64AndBack = Buffer.from(base64, "base64").toString("base64");
        return base64 === base64AndBack;
      }
      default:
        return false;
    }
  },
  // signature is valid
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
];

module.exports = (input, hmacKey = null) => {
  try {
    return checks.every((check) => check(input, hmacKey));
  } catch (e) {
    console.error(e);
    return false;
  }
};
