const fs = require("fs")
const path = require("path")
const { spawn } = require("child_process")
const abi = require("node-abi")

// Examples:
// win32-x64-node-abi108.node
// linux-x64-node-abi108.node
// linux-arm-node-abi108.node
function prebuildName() {
  const runtime = process.release.name || "node"
  const version = process.versions[runtime]
  if (!version) {
    throw new Error(`runtime ${runtime} is not supported`)
  }
  const abiv = abi.getAbi(process.versions[runtime], runtime)
  return `${encodeName(process.platform)}-${encodeName(
    process.arch
  )}-${runtime}-abi${abiv}.node`
}

function encodeName(name) {
  return name.replace(/\//g, "+")
}

// Compute the path we want to emit the binary to
const binaryPath = path.join(__dirname, "index.node")

function isBuilt() {
  return fs.existsSync(binaryPath)
}

function build() {
  spawn("npm", ["run", "build"], { stdio: "inherit", shell: true })
}

if (!isBuilt()) {
  const platformSpecificBinaryPath = path.join(__dirname, 'bin', prebuildName())
  if (fs.existsSync(platformSpecificBinaryPath)) {
    fs.copyFileSync(platformSpecificBinaryPath, binaryPath)
    console.log("Platform specific binary installed.")
  } else {
    console.log("Building from source...")
    build()
  }
}
