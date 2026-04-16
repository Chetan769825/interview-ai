const userModel = require("../models/user.model")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const tokenBlacklistModel = require("../models/blacklist.model")

/**
 * @name registerUserController
 */
async function registerUserController(req, res) {
    try {
        const { username, email, password } = req.body

        if (!username || !email || !password) {
            return res.status(400).json({
                message: "Please provide username, email and password"
            })
        }

        const isUserAlreadyExists = await userModel.findOne({
            $or: [{ username }, { email }]
        })

        if (isUserAlreadyExists) {
            return res.status(400).json({
                message: "Account already exists"
            })
        }

        const hash = await bcrypt.hash(password, 10)

        const user = await userModel.create({
            username,
            email,
            password: hash
        })

        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        )

        // ✅ FIXED COOKIE
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        })

        res.status(201).json({
            message: "User registered successfully",
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
}


/**
 * @name loginUserController
 */
async function loginUserController(req, res) {
    try {
        const { email, password } = req.body

        const user = await userModel.findOne({ email })

        if (!user) {
            return res.status(400).json({
                message: "Invalid email or password"
            })
        }

        const isPasswordValid = await bcrypt.compare(password, user.password)

        if (!isPasswordValid) {
            return res.status(400).json({
                message: "Invalid email or password"
            })
        }

        const token = jwt.sign(
            { id: user._id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "1d" }
        )

        // ✅ FIXED COOKIE (IMPORTANT)
        res.cookie("token", token, {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        })

        res.status(200).json({
            message: "User logged in successfully",
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
}


/**
 * @name logoutUserController
 */
async function logoutUserController(req, res) {
    try {
        const token = req.cookies.token

        if (token) {
            await tokenBlacklistModel.create({ token })
        }

        // ✅ FIXED CLEAR COOKIE
        res.clearCookie("token", {
            httpOnly: true,
            secure: true,
            sameSite: "None"
        })

        res.status(200).json({
            message: "User logged out successfully"
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
}


/**
 * @name getMeController
 */
async function getMeController(req, res) {
    try {
        // ✅ SAFETY CHECK
        if (!req.user) {
            return res.status(401).json({
                message: "Unauthorized"
            })
        }

        const user = await userModel.findById(req.user.id)

        if (!user) {
            return res.status(404).json({
                message: "User not found"
            })
        }

        res.status(200).json({
            message: "User details fetched successfully",
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({ message: "Server error" })
    }
}


module.exports = {
    registerUserController,
    loginUserController,
    logoutUserController,
    getMeController
}