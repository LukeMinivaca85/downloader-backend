require("dotenv").config()

const express = require("express")
const Database = require("better-sqlite3")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const https = require("https")
const path = require("path")
const { v4: uuidv4 } = require("uuid")
const helmet = require("helmet")
const rateLimit = require("express-rate-limit")

const app = express()

app.use(express.json())
app.use(express.static(__dirname))

app.use(helmet())
app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
}))

// ================= DATABASE =================
const db = new Database("database.db")

db.prepare(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE,
  password TEXT
)
`).run()

db.prepare(`
CREATE TABLE IF NOT EXISTS downloads (
  id TEXT PRIMARY KEY,
  url TEXT,
  expires_at INTEGER,
  max_downloads INTEGER,
  downloads_count INTEGER DEFAULT 0
)
`).run()

// ================= AUTH =================
function auth(req,res,next){
  const token = req.headers.authorization?.split(" ")[1]
  if(!token) return res.status(401).json({error:"No token"})

  try{
    req.user = jwt.verify(token,process.env.JWT_SECRET)
    next()
  }catch{
    return res.status(403).json({error:"Invalid token"})
  }
}

// ================= REGISTER =================
app.post("/register",(req,res)=>{
  const {email,password} = req.body

  if(!email || !password)
    return res.status(400).json({error:"Missing data"})

  const hash = bcrypt.hashSync(password,10)

  try{
    db.prepare("INSERT INTO users (email,password) VALUES (?,?)")
      .run(email,hash)

    res.json({message:"Conta criada 🚀"})
  }catch{
    res.status(400).json({error:"User exists"})
  }
})

// ================= LOGIN =================
app.post("/login",(req,res)=>{
  const {email,password} = req.body

  const user = db.prepare("SELECT * FROM users WHERE email=?")
    .get(email)

  if(!user) return res.status(404).json({error:"User not found"})

  const valid = bcrypt.compareSync(password,user.password)
  if(!valid) return res.status(401).json({error:"Wrong password"})

  const token = jwt.sign(
    { id:user.id, email:user.email },
    process.env.JWT_SECRET,
    { expiresIn:"7d" }
  )

  res.json({token})
})

// ================= FILES =================
const files = {
  "editor-pro": "https://lukintosh.com/downloads/editor.zip",
  "engine": "https://lukintosh.com/downloads/engine.zip",
  "cloud": "https://lukintosh.com/downloads/cloud.zip"
}

// ================= REQUEST TRIAL =================
app.post("/request-trial", auth, (req,res)=>{

  const product = req.body.product
  const fileUrl = files[product]

  if(!fileUrl)
    return res.status(400).json({error:"Invalid product"})

  const id = uuidv4()
  const expiresAt = Date.now() + (1000 * 60 * 30)

  db.prepare(`
    INSERT INTO downloads (id,url,expires_at,max_downloads)
    VALUES (?,?,?,?)
  `).run(id,fileUrl,expiresAt,5)

  res.json({
    link: `${process.env.BASE_URL}/download/${id}`
  })
})

// ================= DOWNLOAD PAGE =================
app.get("/download/:id",(req,res)=>{
  res.sendFile(path.join(__dirname,"download.html"))
})

// ================= DOWNLOAD STREAM =================
app.get("/download-file/:id",(req,res)=>{

  const id = req.params.id

  const row = db.prepare("SELECT * FROM downloads WHERE id=?")
    .get(id)

  if(!row) return res.status(404).send("Invalid ❌")

  if(Date.now() > row.expires_at)
    return res.status(403).send("Expirado ⛔")

  if(row.downloads_count >= row.max_downloads)
    return res.status(403).send("Limite atingido 🚫")

  db.prepare(`
    UPDATE downloads
    SET downloads_count = downloads_count + 1
    WHERE id=?
  `).run(id)

  https.get(row.url,(r)=>{

    res.setHeader("Content-Type","application/octet-stream")
    res.setHeader("Content-Disposition","attachment")

    if(r.headers["content-length"])
      res.setHeader("Content-Length", r.headers["content-length"])

    r.pipe(res)

  }).on("error",()=>{
    res.status(500).send("Erro no download")
  })
})

// ================= HOME =================
app.get("/",(req,res)=>{
  res.sendFile(path.join(__dirname,"index.html"))
})

// ================= START =================
const PORT = process.env.PORT || 3000
app.listen(PORT, ()=>console.log("🚀 Rodando na porta", PORT))
