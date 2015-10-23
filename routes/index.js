'use strict'

// Require CleverCore
const CleverCore = require('clever-core')

// Packages dependencies
const express = require('express')
const router = express.Router()
const ejwt = require('express-jwt')
const jwt = require('jsonwebtoken')

// Exports
module.exports = function(UsersApiPackage, app, config, db) {

  const User = db.models.User

  // TODO: isAuthorized && isRevoked
  const isAuthenticated = ejwt({ secret: process.env.JWT_SECRET || 'shhh' })

  function checkSequelizeError (next, err) {
    if (err && err.name) {
      if (['ValidationError', 'SequelizeUniqueConstraintError'].indexOf() === -1 ) {
        if (!err.errors) return next(err)
        const error400 = new Error(err.errors[0].message)
        error400.code = 'BAD_REQUEST'
        return next(error400)
      }
      return next(err)
    }
    next(err)
  }

  function userValidation (req, update) {

    // VALIDATION
    if (update === true) {
      req.checkBody('email', 'email must be a valid email address').optional().isEmail()
      req.checkBody('password', 'password cannot be empty').optional().notEmpty()
      req.checkBody('firstname', 'firstname cannot be empty').optional().notEmpty()
      req.checkBody('lastname', 'lastname cannot be empty').optional().notEmpty()
      req.checkBody('roles', 'roles cannot be empty').optional().notEmpty()
    } else {
      req.checkBody('email', 'email must be a valid email address').isEmail()
      req.checkBody('password', 'password is required').notEmpty()
      req.checkBody('firstname', 'firstname is required').notEmpty()
      req.checkBody('lastname', 'lastname is required').notEmpty()
      req.checkBody('roles', 'roles is required').notEmpty()
    }

    // SANITIZE
    req.sanitizeBody('email').trim()
    req.sanitizeBody('firstname').trim()
    req.sanitizeBody('lastname').trim()
    req.sanitizeBody('roles').trim()

    const errors = req.validationErrors()
    if (errors) {
      const error400 = new Error(errors[0].msg)
      error400.code = 'BAD_REQUEST'
      return error400
    }

    return null

  }

  // Get TiZR Users
  router.get('/users', isAuthenticated, (req, res, next) => {
    User
      .findAll()
      .then(users => {
        res.json(users.map(user => {
          return user.toJSON()
        }))
      })
      .catch(next)
  })

  // Add TiZR User
  router.post('/users', isAuthenticated, (req, res, next) => {

    // VALIDATION
    const error = userValidation(req)
    if (error) return next(error)

    User
      .create(req.body)
      .then(user => {
        res.status(201).json(user.get({plain: true}))
      })
      .catch(checkSequelizeError.bind(null, next))

  })

  // Update TiZR User
  router.put('/users/:id', isAuthenticated, (req, res, next) => {

    // VALIDATION
    const error = userValidation(req, true)
    if (error) return next(error)

    User
      .update(req.body, {
        where: { id: req.params.id }
      })
      .then(affectedRows => {
        // TODO: check why affectedRows is an array instead Integer
        if(affectedRows[0] < 1) throw null
        res.status(202).json({ updated: affectedRows[0] })
      })
      .catch(checkSequelizeError.bind(null, next))

  })

  // Delete TiZR User
  router.delete('/users/:id', isAuthenticated, (req, res, next) => {

    models.sequelize.transaction(t => {
      return Token
        .destroy({
          where: { user_id: req.params.id }
        }, { transaction: t })
        .then(() => {
          return User
            .destroy({
              where: { id: req.params.id }
            })
        })
    })
    .then(affectedRows => {
      if(affectedRows < 1) throw null
      res.status(202).json({ deleted: affectedRows })
    })
    .catch(next)

  })

  // TiZR User auth
  router.post('/users/authenticate', (req, res, next) => {

    req.checkBody('email', 'email must be a valid email address').isEmail()
    req.checkBody('password', 'password is required').notEmpty()

    const errors = req.validationErrors()
    if (errors) {
      const error400 = new Error(errors[0].msg)
      error400.code = 'BAD_REQUEST'
      return next(error400)
    }

    // find the user
    User
      .findOne({
        where: { email: req.body.email }
      })
      .then(user => {

        if (!user) {

          const error401User = new Error('Authentication failed because user has not been found')
          error401User.code = 'UNAUTHORIZED'
          return next(error401User)

        } else if (user) {

          // check if password matches
          if (user.get('hashed_password') !== user.hashPassword(req.body.password)) {
            const error401Passowrd = new Error('Authentication failed because password is wrong')
            error401Passowrd.code = 'UNAUTHORIZED'
            return next(error401Passowrd)
          } else {

            // if user is found and password is right create a token
            const token = jwt.sign(user.toJSON(), process.env.JWT_SECRET || 'shhh', {
              expiresInMinutes: 1440 // expires in 24 hours
            })

            // return the information including token as JSON
            res
              .status(202)
              .json({
                token: token
              })
          }

        }
      })
      .catch(next)

  })

  // Exta
  router.post('/users/hash-password', (req, res, next) => {

    req.checkBody('password', 'password is required').notEmpty()

    const errors = req.validationErrors()
    if (errors) {
      const error400 = new Error(errors[0].msg)
      error400.code = 'BAD_REQUEST'
      return next(error400)
    }

    const salt = User.makeSalt()
    const hashedPassword = User.hashPassword(req.body.password, salt)

    res
      .status(202)
      .json({
        password: req.body.password,
        salt: salt,
        hashedPassword: hashedPassword
      })
  })


  module.exports = router

  return router

}
