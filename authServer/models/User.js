const mongoose = require('mongoose');
const Schema = mongoose.Schema;
mongoose.Promise = global.Promise;
const md5 = require('md5');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sid = require('shortid');

const userSchema = new Schema(
  {
    _id: {
      type: String,
      default: sid.generate,
    },
    email: {
      type: String,
      unique: true,
      lowercase: true,
      trim: true,
      validate: [validator.isEmail, 'Invalid Email Address'],
      required: 'Please supply a valid Email Address',
    },
    name: {
      type: String,
      required: 'Please supply a name',
      trim: true,
    },
    password: {
      type: String,
      required: 'Please supply a password',
      trim: true,
    },
    resetPasswordToken: String,
    resetPasswordExpires: Date,
  },
  {
    timestamps: true,
  }
);

userSchema.pre('save', async function (next) {
  if (!this.isModified('password')) {
    next();
  }

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.matchPassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};
userSchema.methods.getSignedJwtToken = function () {
  return {
    token: jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRE,
    }),
  };
};

userSchema.virtual('gravatar').get(function () {
  const hash = md5(this.email);
  return `https://gravatar.com/avatar/${hash}?s=200`;
});

module.exports = mongoose.model('User', userSchema);
