var WhisperAPI = {
  basic_auth: '',

  call: function(method, path, data, callback) {
    var xhr = new XMLHttpRequest();
    xhr.open(method, "https://textsecure-service.whispersystems.org" + path);
    xhr.setRequestHeader("Authorization", this.basic_auth);

    // Track the state changes of the request
    xhr.onreadystatechange = function() {
      // Ready state 4 means the request is done
      if(xhr.readyState === 4) {
        callback && callback(xhr.responseXML);
      }
    }

    xhr.send(data);
  },

  register: function(email_address) {
    this.call('GET', '/v1/accounts/email/code/' + email_address);
  },

  login: function(email_address, password) {
    this.basic_auth = 'Basic ' + btoa(email_address + ':' + password);
  },

  verify_registration: function(verification_code, signalingKey, registrationId) {
    var data = {
      "signalingKey"   : signalingKey,
      "supportSms"     : false,
      "registrationId" : registrationId
    };
    this.call('PUT', '/v1/acccounts/code/' + verification_code, data);
  },

  register_gcm: function(gcm_registration_id) {
    var data = { 'gcmRegistrationId' : gcm_registration_id };
    this.call('PUT', '/v1/accounts/gcm/', data);
  },

  register_prekeys: function(keys) {
    this.call('PUT', '/v1/keys/', keys);
  },

};
