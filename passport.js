const JwtStrategy = require('passport-jwt').Strategy

module.exports = function (config, database, passport) {
  const opts = {}

  opts.secretOrKey = process.env.JWT_SECRET || 'shhh'
  // opts.issuer = 'accounts.examplesoft.com'
  // opts.audience = 'yoursite.net'

  passport.use(new JwtStrategy(opts, (jwtPayload, done) => {
    const User = database.models.User
    User.findOne({
      where: { id: jwtPayload.id }
    }, (err, user) => {
      if (err) return done(err, false)
      if (!user) return done(null, false)
      done(null, user)
    })
  }))
}
