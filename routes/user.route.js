const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

let tokenList = {}

router.post('/signup', function (req, res) {
    console.log(req.body);
    bcrypt.hash(req.body.password, 10, function (err, hash) {
        if (err) {
            return res.status(500).json({
                error: err
            });
        }
        else {
            const user = new User({
                _id: new mongoose.Types.ObjectId(),
                email: req.body.email,
                password: hash
            });
            user.save().then(function (result) {
                console.log(result);
                res.status(200).json({
                    success: 'New user has been created'
                });
            }).catch(error => {
                res.status(500).json({
                    error: err
                });
            });
        }
    });
});

router.post('/signin', (req, res) => {
    User.findOne({ email: req.body.email })
        .exec()
        .then(function (user) {
            bcrypt.compare(req.body.password, user.password, function (err, result) {
                if (err) {
                    return res.status(401).json({
                        failed: 'Unauthorized Access'
                    });
                }
                if (result) {
                    const JWTToken = jwt.sign({
                        email: user.email,
                        _id: user._id
                    },
                        'secret',
                        {
                            expiresIn: '2h'
                        });

                    const refreshToken = jwt.sign({
                        email: user.email,
                        _id: user._id
                    }, 'secret', { expiresIn: '5h' })


                    tokenList[refreshToken] = refreshToken
                    return res.status(200).json({
                        success: 'Welcome to the JWT Auth',
                        token: JWTToken,
                        refreshToken: refreshToken,
                        tokenList: tokenList
                    });
                }
                return res.status(401).json({
                    failed: 'Unauthorized Access'
                });
            });
        })
        .catch(error => {
            res.status(500).json({
                error: error
            });
        });
});


router.use(require('../tokenChecker'))


router.post('/token', (req, res) => {
    const postData = req.body

    if ((postData.refreshToken && postData.refreshToken in tokenList)) {
        const refreshToken = jwt.sign({
            email: postData.email,
            _id: '5ba9cfa0d1cc8733f407b186'
        },
            'secret',
            {
                expiresIn: '2h'
            });

        // update the token in the list
        tokenList[postData.refreshToken] = refreshToken
        return res.status(200).json({
            success: 'Refresh Token',
            refreshToken: refreshToken
        });
    } else {
        return res.status(401).json({
            failed: 'no tokenlist',
            tokenList: tokenList
        });
    }


});

router.get('/secure', (req, res) => {
    // all secured routes goes here
    res.send('I am secured...')
})


module.exports = router;