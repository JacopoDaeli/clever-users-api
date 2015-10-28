'use strict'

const cleverCore = require('clever-core')
const Package = cleverCore.Package

// Defining the Package
var UsersApiPackage = new Package('users-api')

// All CLEVER packages require registration
UsersApiPackage
  .attach({
    where: '/'
  })
  .routes(['app', 'config', 'database', 'auth'])
  .models()
  .register()

// Register auth
cleverCore.register('auth', (config, database, passport) => {
  require('./passport')(config, database, passport)

  // TODO: isAuthorized
  const auth = {
    authenticate: passport.authenticate.bind(passport)
  }

  return auth
})
