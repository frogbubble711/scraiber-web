const mongoose = require('mongoose');

const { Schema } = mongoose;
// Create Schema
const TokenSchema = new Schema({
  _userId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    ref: 'User',
  },
  token: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    expires: 43200,
  },
});
module.exports = Token = mongoose.model('token', TokenSchema);