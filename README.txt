fisilchat
=========

secure Javascript chat: node.js, socket.io, sjcl

This project contains code for a client and server that together implement encrypted text chat. Both use the Stanford Javascript Crypto Library for:
- symmetric key encryption for the sockets
- public key encryption for the messages
- PBKDF2 for storing the hashed password

In fact we use a fork of the SJCL ECC branch, with serialization added: https://github.com/justindthomas/sjcl/tree/serialization

The server is unable to decrypt the messages as they pass through.

Included are the Procfile and package.json needed to run as a Heroku app.

Todo:
- integrate with http://candy-chat.github.com/candy/ UI
- support the secure storing of data on the server, and use this to store contacts
- have server store messages, that only recipients can decrypt later
