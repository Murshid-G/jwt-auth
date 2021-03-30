var mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const confiq=require('../config/config').get(process.env.NODE_ENV);
const salt = 10;
const bcrypt = require('bcrypt')
 const userSchema = mongoose.Schema({
     name:{
         type:String,
         required: true,

     },
     email:{
         type:String,
         required:true,
         unique: 1
     },
     mobile:{
         type: Number,
         required:true
     },
     password:{
         type: String,
         required:true,
         minlength:8
                    
     },
     password2:{
        type: String,
        required:true,
        minlength:8
     },
     token:{
         type: String
     }
 })
 userSchema.pre('save',(next)=>{
     var user=this;
     if(user.isModified('password')){
         bcrypt.genSalt(salt,(err,salt)=>{
             if(err) 
             return next(err);
             bcrypt.hash(user.password, salt, (err,hash)=>{
                if(err) 
                return next(err);
                user.password=hash;
                user.password2=hash;
                next()
             })
         })
     }
     else next();
 })
 userSchema.methods.comparepassword=(password,cb)=>{
     bcrypt.compare(password,this.password,(err,inMatch)=>{
         if(err) return cb(next);
         cb(null, isMatch)
     })
 }
 userSchema.methods.generateToken=function(cb){
    var user =this;
    var token=jwt.sign(user._id.toHexString(),confiq.SECRET);

    user.token=token;
    user.save(function(err,user){
        if(err) return cb(err);
        cb(null,user);
    })
}
userSchema.statics.findByToken=function(token,cb){
    var user=this;

    jwt.verify(token,confiq.SECRET,function(err,decode){
        user.findOne({"_id": decode, "token":token},function(err,user){
            if(err) return cb(err);
            cb(null,user);
        })
    })
};
userSchema.methods.deleteToken=function(token,cb){
    var user=this;

    user.update({$unset : {token :1}},function(err,user){
        if(err) return cb(err);
        cb(null,user);
    })
}
 module.exports = mongoose.model('User',userSchema)