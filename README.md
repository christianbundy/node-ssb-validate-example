# Node.js SSB Validate Example

Don't use this! This is an experimental module that's meant to validate SSB
messages, but it's not restrictive enough. It _will_ allow invalid messages and
you definitely shouldn't use it.

Right now this passes 99 out of 100 tests, and I think the last test failure is
a bug? More info here, probably: https://github.com/ssbc/ssb-validate/pull/21

Anyway, please add more fixtures so that we're forced to implement more
validator behavior! I don't want to write any code that isn't being tested, so
I'm waiting to write more code until I can find some better test fixtures.

## Getting started

```sh
npm install
npm test
```

## License

AGPL-3.0
