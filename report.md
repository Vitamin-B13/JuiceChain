# JuiceChain 渗透测试报告

## 1. 概要
- 目标：http://192.168.204.24:3000
- 扫描时间：2026-03-03 03:45:45 UTC
- 工具版本：1.0.0
- 结果摘要：1 个高危 / 0 个中危 / 0 个低危

## 2. 目标信息
- 存活状态：True，响应时间：35 ms
- 技术指纹：服务器=unknown，框架=unknown，hints=[]
- 安全头审计：缺失=['Strict-Transport-Security', 'Content-Security-Policy', 'Referrer-Policy', 'Permissions-Policy']；已存在={'X-Frame-Options': 'SAMEORIGIN', 'X-Content-Type-Options': 'nosniff'}；过时头={'Feature-Policy': "payment 'self'"}
- 首页：http://192.168.204.24:3000/ (状态码=200)

## 3. 攻击面
- 发现页面数量：1
- SPA 路由数量：143
- API 端点数量：42
- 分类统计：服务器端点=5 / SPA 路由=4 / 噪声=68

### SPA 路由列表
- `#/2fa/enter`
- `#/403`
- `#/about`
- `#/accounting`
- `#/address/create`
- `#/address/saved`
- `#/address/select`
- `#/administration`
- `#/basket`
- `#/bee-haven`
- `#/change-password`
- `#/chatbot`
- `#/complain`
- `#/contact`
- `#/data-export`
- `#/delivery-method`
- `#/deluxe-membership`
- `#/forgot-password`
- `#/hacking-instructor`
- `#/juicy-nft`
- `#/last-login-ip`
- `#/login`
- `#/order-history`
- `#/order-summary`
- `#/photo-wall`
- `#/privacy-policy`
- `#/privacy-security`
- `#/recycle`
- `#/register`
- `#/saved-payment-methods`
- `#/score-board`
- `#/search`
- `#/track-result`
- `#/track-result/new`
- `#/two-factor-authentication`
- `#/wallet`
- `#/wallet-web3`
- `#/web3-sandbox`
- `/10`
- `/16`
- ... 其余 103 项省略

### API 端点列表
- `/api/Addresss`
- `/api/BasketItems`
- `/api/Cards`
- `/api/Challenges`
- `/api/Challenges/?key=nftMintChallenge`
- `/api/Complaints`
- `/api/Deliverys`
- `/api/Feedbacks`
- `/api/Hints`
- `/api/Products`
- `/api/Quantitys`
- `/api/Recycles`
- `/api/SecurityAnswers`
- `/api/SecurityQuestions`
- `/api/Users`
- `/rest/admin`
- `/rest/captcha`
- `/rest/chatbot`
- `/rest/continue-code`
- `/rest/continue-code-findIt`
- `/rest/continue-code-findIt/apply/`
- `/rest/continue-code-fixIt`
- `/rest/continue-code-fixIt/apply/`
- `/rest/continue-code/apply/`
- `/rest/country-mapping`
- `/rest/deluxe-membership`
- `/rest/image-captcha/`
- `/rest/memories`
- `/rest/order-history`
- `/rest/products`
- `/rest/repeat-notification`
- `/rest/saveLoginIp`
- `/rest/track-order`
- `/rest/user`
- `/rest/user/authentication-details/`
- `/rest/user/change-password?current=`
- `/rest/user/login`
- `/rest/user/reset-password`
- `/rest/user/security-question?email=`
- `/rest/user/whoami`
- ... 其余 2 项省略

## 4. 漏洞发现

| 严重程度 | 类型 | 路径 | 参数 | Payload | 证据 | 响应状态码 |
| --- | --- | --- | --- | --- | --- | --- |
| critical | AUTH_BYPASS | /rest/user/login | email | ' OR 1=1-- | login bypass succeeded: baseline status=401, bypass status=200, response contains auth token | 200 |
| high | SQLI_ERROR | /rest/user/login | email | ' | possible SQL error keyword in response: ...... | 500 |

## 5. 建议
- 所有数据库访问使用参数化查询或 ORM 绑定变量，禁止字符串拼接 SQL。