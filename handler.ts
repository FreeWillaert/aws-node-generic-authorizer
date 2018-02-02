'use strict';

// Public API
module.exports.publicEndpoint = (event, context, cb) => {
  cb(null, { body: 'Welcome to our Public API!\nevent:' + JSON.stringify(event,null,2)+"\n\ncontext:\n"+JSON.stringify(context) });
};

// Private API
module.exports.privateEndpoint = (event, context, cb) => {
  cb(null, { body: 'Only logged in users can see this\nevent:' + JSON.stringify(event,null,2)+"\n\ncontext:\n"+JSON.stringify(context) });
};
