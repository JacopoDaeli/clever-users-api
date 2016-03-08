'use strict'

const crypto = require('crypto')

module.exports = function (sequelize, DataTypes) {
  const User = sequelize.define('User', {
    id: { type: DataTypes.INTEGER, autoIncrement: true, primaryKey: true },
    email: { type: DataTypes.STRING, unique: true, allowNull: false },
    password: {
      type: DataTypes.VIRTUAL,
      set (pwd) {
        this.setDataValue('password', pwd)
        this.salt = this.makeSalt()
        this.setDataValue('hashed_password', this.hashPassword(pwd))
      },
      validate: {
        isLongEnough (val) {
          if (val.length < 7) {
            throw new Error('Password must be longer')
          }
        }
      }
    },
    hashed_password: DataTypes.STRING,
    salt: DataTypes.STRING,
    firstname: { type: DataTypes.STRING, allowNull: true },
    lastname: { type: DataTypes.STRING, allowNull: true },
    roles: {
      type: DataTypes.ARRAY(DataTypes.STRING),
      set (role) {
        let roles = [role]
        if (this.roles) roles = this.roles.concat(roles)
        this.setDataValue('roles', roles)
      },
      allowNull: true
    }
  }, {
    paranoid: true,
    underscored: true,
    tableName: 'user',
    classMethods: {
      associate (models) {
        // Maybe one day :-)
      },
      makeSalt () {
        return crypto.randomBytes(16).toString('base64')
      },
      hashPassword (password, salt) {
        if (!password || !salt) return ''
        const salt64 = new Buffer(salt, 'base64')
        return crypto.pbkdf2Sync(password, salt64, 10000, 64).toString('base64')
      }
    },
    instanceMethods: {
      makeSalt () {
        return crypto.randomBytes(16).toString('base64')
      },
      hashPassword (password) {
        if (!password || !this.salt) return ''
        const salt = new Buffer(this.salt, 'base64')
        return crypto.pbkdf2Sync(password, salt, 10000, 64).toString('base64')
      },
      toJSON () {
        const obj = this.get({ plain: true })
        delete obj.hashed_password
        delete obj.salt
        obj.role = this.roles[0]
        return obj
      }
    }
  })

  return User
}
