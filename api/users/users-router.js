const router = require("express").Router();

const Users = require("./users-model.js");

//----------------------------------------------------------------------------//
// Note that a call to GET /api/users is protected by our "restricted"
// middleware. THAT MIDDLEWARE IS SET UP GLOBALLY IN THE server.js FILE. We
// don't have to do anything here, because a request for GET /api/users will
// first be handled by the restricted middleware, which checks to see if a
// req.session.user object exists. If it does, processing is allowed to
// continue, so if we ever reach this request handler, it's because the
// restricted middleware determined that the session exists, is not expired, and
// has the .user object (which can only be added by a successful login.)
//----------------------------------------------------------------------------//
router.get("/", (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

module.exports = router;
