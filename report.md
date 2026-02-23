# JuiceChain Report

- Version: 0.5.0
- Timestamp: 1771855652
- Duration(ms): 423
- Target: 192.168.204.24:3000

## Liveness

- Alive: True
- Status: 200
- RTT(ms): 22

## Passive Info

- Homepage URL: http://192.168.204.24:3000/
- Status: 200
- Title: OWASP Juice Shop
- Fingerprint: server=None x_powered_by=None hints=[]
- Missing security headers: ['Strict-Transport-Security', 'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy']
- Deprecated security headers present: {'Feature-Policy': "payment 'self'"}
- SPA hints: {'hash_route_hints': [{'header': 'X-Recruiting', 'value': '/#/jobs', 'hash_route': '/#/jobs'}], 'hash_routes_in_html': []}

## Attack Surface Enumeration

- Pages fetched: 1
- Hash routes (from html/headers): ['#/jobs']
- SPA routes (from assets): ['#/wallet-web3']
- API candidates (from assets): ['/api/Addresss', '/api/BasketItems', '/api/Cards', '/api/Challenges', '/api/Challenges/?key=nftMintChallenge', '/api/Complaints', '/api/Deliverys', '/api/Feedbacks', '/api/Hints', '/api/Products', '/api/Quantitys', '/api/Recycles', '/api/SecurityAnswers', '/api/SecurityQuestions', '/api/Users', '/rest/admin', '/rest/captcha', '/rest/chatbot', '/rest/continue-code', '/rest/continue-code-findIt', '/rest/continue-code-findIt/apply/', '/rest/continue-code-fixIt', '/rest/continue-code-fixIt/apply/', '/rest/continue-code/apply/', '/rest/country-mapping', '/rest/deluxe-membership', '/rest/image-captcha/', '/rest/memories', '/rest/order-history', '/rest/products', '/rest/repeat-notification', '/rest/saveLoginIp', '/rest/track-order', '/rest/user', '/rest/user/authentication-details/', '/rest/user/change-password?current=', '/rest/user/login', '/rest/user/reset-password', '/rest/user/security-question?email=', '/rest/user/whoami', '/rest/wallet/balance', '/rest/web3']

- Server endpoints: 3
- SPA routes mapped: 0
- Fallback noise: 10
