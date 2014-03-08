var Whisper = new function() {

  this.PreKeyMessage = dcodeIO.ProtoBuf.
                       loadProtoFile("./WhisperTextProtocol.proto").
                       build("PreKeyWhisperMessage");

  this.KeyPair = function() {
    var mysecret = crypto.getRandomValues(new Uint8Array(32));
    mysecret[0] &= 248;
    mysecret[31] &= 127;
    mysecret[31] |= 64;
    this.sk = c255lbase32encode(mysecret);
    this.pk = curve25519b32(this.sk);
  };

  this.KeyPair.prototype.to_a = function() {
    var a = new Uint16Array(16);
    a.set(c255lbase32decode(this.pk));
    return a;
  };
}();


window.onload = function() {

  var identity_key = new Whisper.KeyPair();
  document.getElementById('privatekey').innerHTML = identity_key.sk;
  document.getElementById('publickey').innerHTML  = identity_key.pk;

  var registrationid = crypto.getRandomValues(new Uint8Array(32));

  var BATCH_SIZE = 25;
  var prekeys = [];
  var prekey_protos = [];
  for (var i=0; i < BATCH_SIZE; i++) {
    var prekey = new Whisper.KeyPair();

    prekeys[i] = {
      id:          i,
      private_key: prekey.sk,
      public_key:  prekey.pk
    };

    document.getElementById('prekeys').innerText +=
      "  [" + i + "]\n      pub: " + prekey.pk + "\n      priv: " + prekey.sk;

    prekey_protos[i] = new Whisper.PreKeyMessage(
      registrationid,
      i,
      prekey.to_a(),
      identity_key.to_a()
    );

    document.getElementById('prekeys').innerText +=
      "\n      " + "proto: " + prekey_protos[i].encode64() + "\n\n";
  }
};
