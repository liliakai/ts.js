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

var WhisperAPI = new function() {
  var PUSH_URL = "https://textsecure-service.whispersystems.org";
  this.basic_auth = '';

  this.call = function(method, path, data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open(method, PUSH_URL + path);
    xhr.setRequestHeader("Authorization", this.basic_auth);

    // Track the state changes of the request
    xhr.onreadystatechange = function() {
      // Ready state 4 means the request is done
      if(xhr.readyState === 4) {
        callback && callback(xhr.responseXML);
      }
    }

    xhr.send(data);
  };

  this.register = function(email_address) {
    this.call('GET', '/v1/accounts/email/code/' + email_address);
  };

  this.login = function(email_address, password) {
    this.basic_auth = 'Basic ' + btoa(email_address + ':' + password);
  };

  this.verify_registration = function(verification_code, signalingKey, registrationId) {
    var data = {
      "signalingKey"   : signalingKey,
      "supportSms"     : false,
      "registrationId" : registrationId
    };
    this.call('PUT', '/v1/acccounts/code/' + verification_code, data);
  };

  this.register_gcm = function(gcm_registration_id) {
    var data = { 'gcmRegistrationId' : gcm_registration_id };
    this.call('PUT', '/v1/accounts/gcm/', data);
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
