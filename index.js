const sodium = require("sodium-native");

const isCanonicalBase64 = (base64String) => {
  return (
    base64String === Buffer.from(base64String, "base64").toString("base64")
  );
};

const validateContentType = {
  object: (value) => {
    return (
      value !== null &&
      Array.isArray(value) === false &&
      typeof value.type === "string" &&
      value.type.length >= 3 &&
      value.type.length <= 52
    );
  },
  string: (value) => {
    return isCanonicalBase64(value.split(".box")[0]);
  },
};

const getPayload = (hmacKey, unsignedUtf8) => {
  const out = Buffer.alloc(sodium.crypto_auth_BYTES);
  const key = Buffer.from(hmacKey, "base64");
  sodium.crypto_auth(out, unsignedUtf8, key);
  return out;
};

const isHmacValid = (hmacKey) => {
  return (
    typeof hmacKey === "string" &&
    Buffer.from(hmacKey, "base64").length === sodium.crypto_auth_KEYBYTES
  );
};

// TODO: Rename this function
const f = (signatureBytes, unsignedUtf8, publicKeyBytes, hmacKey) => {
  return hmacKey === null
    ? sodium.crypto_sign_verify_detached(
        signatureBytes,
        unsignedUtf8,
        publicKeyBytes
      )
    : typeof hmacKey === "string" &&
        isHmacValid(hmacKey) &&
        sodium.crypto_sign_verify_detached(
          signatureBytes,
          getPayload(hmacKey, unsignedUtf8),
          publicKeyBytes
        );
};

const validateSignature = (unsignedMessage, signature, hmacKey) => {
  const authorSuffix = ".ed25519";
  const signatureSuffix = ".sig.ed25519";

  // When checking signatures, we need to use UTF-8.
  const unsignedUtf8 = Buffer.from(
    JSON.stringify(unsignedMessage, null, 2),
    "utf8"
  );

  const publicKeyChars = unsignedMessage.author.slice(
    1,
    unsignedMessage.author.length - authorSuffix.length
  );
  const publicKeyBytes = Buffer.from(publicKeyChars, "base64");

  const signatureChars = signature.slice(
    0,
    signature.length - signatureSuffix.length
  );
  const signatureBytes = Buffer.from(signatureChars, "base64");

  return (
    isCanonicalBase64(publicKeyChars) &&
    publicKeyBytes.length === sodium.crypto_sign_PUBLICKEYBYTES &&
    signatureBytes.length === sodium.crypto_sign_BYTES &&
    isCanonicalBase64(signatureChars) &&
    f(signatureBytes, unsignedUtf8, publicKeyBytes, hmacKey)
  );
};

module.exports = (
  message,
  hmacKey = null,
  state = { id: null, sequence: 0 }
) => {
  const keyValidators = {
    previous: (value, index) => {
      return index === 0 && value === state.id;
    },
    author: (value, index) => {
      const authorSuffix = ".ed25519";
      return (
        (index === 1 || index === 2) &&
        typeof value === "string" &&
        value.endsWith(authorSuffix)
      );
    },
    sequence: (value, index) => {
      return (index === 1 || index === 2) && value === state.sequence + 1;
    },
    timestamp: (value, index) => {
      return index === 3 && typeof value === "number";
    },
    hash: (value, index) => {
      return index === 4 && value === "sha256";
    },
    content: (value, index) => {
      return (
        index === 5 &&
        typeof validateContentType[typeof value] === "function" &&
        validateContentType[typeof value](value, index)
      );
    },
    signature: (value, index) => {
      const suffix = ".sig.ed25519";

      return (
        index === 6 &&
        typeof value === "string" &&
        value.endsWith(suffix) &&
        validateSignature(
          Object.fromEntries(
            Object.entries(message).filter(([key]) => key !== "signature")
          ),
          value,
          hmacKey
        )
      );
    },
  };
  return (
    typeof message === "object" &&
    message !== null &&
    Array.isArray(message) === false &&
    // Usually when we encode a message we use Latin-1.
    Buffer.from(JSON.stringify(message, null, 2), "latin1").byteLength <=
      8192 &&
    Object.keys(message).length === 7 &&
    Object.entries(message).every(([key, value], index) => {
      return (
        typeof keyValidators[key] === "function" &&
        keyValidators[key](value, index)
      );
    })
  );
};
