const fs = require("fs").promises;
const path = require("path");
const tap = require("tap");

const isValid = require(".");

const testData = (...args) => path.join(__dirname, "fixtures", ...args);

fs.readFile(testData("maybe.json")).then((valid) => {
  const entries = JSON.parse(valid);
  entries.forEach((message) => {
    const state = message.state ? message.state : undefined
    const result = isValid(message.msg, message.cap, state);
    tap.equal(result, message.valid, message.msg);
  });
});

fs.readFile(testData("invalid.json")).then((valid) => {
  const entries = JSON.parse(valid);
  entries.forEach((message) => {
    const result = isValid(message);
    tap.equal(result, false, message);
  });
});
