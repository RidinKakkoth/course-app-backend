const User=require('../model/User')
const bcrypt=require("bcrypt")
const jwt=require('jsonwebtoken')

const createToken=(id)=>{
    return  jwt.sign({id:id},"secretCodeforUser",{expiresIn:'3d'})
}

const registerUser=async(req,res)=>{

    try {
        const {name, email, password } = req.body;
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ msg: 'User already exists' });
        }

        const hashPassword= await bcrypt.hash(password,10)

        user = new User({
            name,
            email,
            password:hashPassword
        });

        await user.save();

        res.json({ msg: 'User registered successfully' });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
}

const userLogin=async(req,res)=>{
    try {
        const { email, password } = req.body;

        let userLogin={
            status: false,
            token: null,
            name:null
        }
    
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid credentials' });
        }
        
        const token=createToken(user._id)
        userLogin.token = token;
        userLogin.status = true;
        userLogin.name = user.name;
        res.json({ userLogin })

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server Error');
    }
}