const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const createHttpError = require('http-errors');
const { roles } = require('../utils/constants');


/*  Set up email and password, all new accounts are automatically assigned role of patient */
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    lowercase: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: [roles.admin, roles.doctor, roles.patient, roles.nurse],
    default: roles.patient,
  },
});

/*  Hash password and read if registering user is the admin account */
UserSchema.pre('save', async function (next) {
  try {
    /* Hash the password with salt and save */
    if (this.isNew) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(this.password, salt);
      this.password = hashedPassword;
      /* if user logs in with default admin email, automatically assign admin role */
      if (this.email === process.env.ADMIN_EMAIL.toLowerCase()) {
        this.role = roles.admin;
      }
    }
    next();
  } catch (error) {
    next(error);
  }
});

/*  Compare password with hash password */
UserSchema.methods.isValidPassword = async function (password) {
  try {
    return await bcrypt.compare(password, this.password);
  } catch (error) {
    throw createHttpError.InternalServerError(error.message);
  }
};

const User = mongoose.model('user', UserSchema);
module.exports = User;