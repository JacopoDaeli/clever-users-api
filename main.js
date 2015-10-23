'use strict'

const cleverCore = require('clever-core')
const Package = cleverCore.Package

// Defining the Package
var UsersApiPackage = new Package('users-api')

// All CLEVER packages require registration
UsersApiPackage
  .attach({
    where: '/users'
  })
  .routes(['app', 'config', 'database'])
  .models()
  .register()
