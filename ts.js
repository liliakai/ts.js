window.onload = function() {
  var WhisperTextProtocol = dcodeIO.ProtoBuf.loadProtoFile("./WhisperTextProtocol.proto");
  var PreKeyWhisperMessage = WhisperTextProtocol.build("PreKeyWhisperMessage");

  var registrationid = crypto.getRandomValues(new Uint8Array(32));
  var mysecret = crypto.getRandomValues(new Uint8Array(32));

  mysecret[0] &= 248;
  mysecret[31] &= 127;
  mysecret[31] |= 64;
  var privkey = c255lbase32encode(mysecret);
  var pubkey = curve25519b32(privkey);
  document.getElementById('privatekey').innerHTML = privkey;
  document.getElementById('publickey').innerHTML = pubkey;

  var BATCH_SIZE = 25;
  var prekeys = [];
  var prekey_protos = [];
  for (var i=0; i < BATCH_SIZE; i++) {
    var prekey_priv = crypto.getRandomValues(new Uint8Array(32));
    prekey_priv[0] &= 248;
    prekey_priv[31] &= 127;
    prekey_priv[31] |= 64;
    var prekey_priv = c255lbase32encode(prekey_priv);
    var prekey_pub = curve25519b32(prekey_priv);

    prekeys[i] = {id: i, private_key: prekey_priv, public_key: prekey_pub};
    document.getElementById('prekeys').innerText += (i != 0 ? "\n" : "") + "    [" + i + "]\n        pub: " + prekey_pub + "\n       priv: " + prekey_priv;

    var baseKey = new Uint16Array(16);
    baseKey.set(c255lbase32decode(prekey_pub));

    var identityKey = new Uint16Array(16);
    identityKey.set(c255lbase32decode(pubkey));
    prekey_protos[i] = new PreKeyWhisperMessage(registrationid, i, baseKey, identityKey);
    document.getElementById('prekeys').innerText += "\n      " + "proto: " + prekey_protos[i].encode64() + "\n";

  }
};
