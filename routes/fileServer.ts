/*
 * Copyright (c) 2014-2023 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path = require('path')
import { Request, Response, NextFunction } from 'express'
import challengeUtils = require('../lib/challengeUtils')

const utils = require('../lib/utils')
const security = require('../lib/insecurity')
const challenges = require('../data/datacache').challenges

module.exports = function servePublicFiles () {
  return (req: Request, res: Response, next: NextFunction) => {

    const params = req.params;
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, req, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, req: Request, next: NextFunction) {
    
    // ssrfSecretsChallenge
    if(file && file.includes("password-list.png")){

      const ip = req.socket.remoteAddress;
      if(ip == "::1" || ip=="0.0.0.0" || ip?.includes("127.0.0.1") || ip?.includes("172.17.0.1")){

        // Solve challenge only if the User-Agent is JuiceShop. This is not a security feature, but simply to prevent that
        // users solve the challenge by accidence if the shop is running on localhost
        if(req.get('User-Agent') == "JuiceShop"){
          challengeUtils.solveIf(challenges.ssrfSecretsChallenge, () => { return true})
          res.sendFile(path.resolve('ftp/', file))
          return
        }
      }
      else{
        // Only allow localhost
        res.status(403)
        next(new Error('Only requests from localhost can access this secret file! Your IP is: ' + ip))
        return;
      }
    }
    
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      res.sendFile(path.resolve('ftp/', file))
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
