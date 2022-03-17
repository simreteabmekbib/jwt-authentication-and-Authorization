require('dotenv').config()

const express = require('express')
const app = express()
const jwt = require('jsonwebtoken')

app.use(express.json())

let refreshTokens =[] //in real project this variable must store in database cause every time we refresh the page it will empty
app.use('/token', (req, res)=>{
    const refreshToken = req.body.token
    if (refreshToken == null) return res.sendStatus(401)
    if (!refreshTokens.includes(refreshToken)) return res.sendStatus(403)
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if(err) return res.sendStatus(403)
        const accessToken = generateAccessToken({name: user.name})
        res.json({ accessToken: accessToken })
    }) 
})

app.delete('/logout', (req, res)=>{
    refreshTokens = refreshTokens.filter(token => token !== req.body.token)
    res.sendStatus(204)
})
app.post('/login',(req, res)=>{
  // Authenticate User
  const username = req.body.username;
  //const password = req.body.password;
  const user = {name:username}
  const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
  const accessToken=generateAccessToken(user)
  refreshTokens.push(refreshToken)
  res.json({accessToken:accessToken, refreshToken:refreshToken})
})

function generateAccessToken(user){
    return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {expiresIn: '1m'})
}

app.listen(4000)