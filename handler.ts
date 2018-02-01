'use strict';

// Public API
module.exports.publicEndpoint = (event, context, cb) => {
  cb(null, { body: 'Welcome to our Public API!' });
};

// Private API
module.exports.privateEndpoint = (event, context, cb) => {
  cb(null, { body: 'Only logged in users can see this' });
};
