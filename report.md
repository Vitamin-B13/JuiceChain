# JuiceChain 安全测试报告

## 1. 执行概览
- 目标：`http://192.168.204.24:3000`
- 扫描时间：2026-03-07 12:44:49 UTC
- 工具版本：1.0.0
- 连通性：存活（状态码=200，响应时间=26 ms）
- 漏洞数据：已提供（包含主动验证结果）
- 漏洞统计：严重 1 | 高危 0 | 中危 0 | 低危 0 | 信息 0 | 总计 1

## 2. 目标与攻击面
### 2.1 目标指纹
- 首页：http://192.168.204.24:3000/（状态码=200）
- 服务端：unknown；框架：unknown；线索：[]
- 安全响应头：缺失=["Strict-Transport-Security", "Content-Security-Policy", "Referrer-Policy", "Permissions-Policy"]；已存在=["X-Frame-Options", "X-Content-Type-Options"]；过时=["Feature-Policy"]

### 2.2 攻击面统计
| 指标 | 数量 |
| --- | --- |
| 页面链接 | 1 |
| SPA 路由 | 143 |
| SPA 路径片段 | 38 |
| Hash 路由 | 1 |
| API 候选端点 | 52 |
| 服务端端点 | 5 |
| SPA 路由映射 | 4 |
| Fallback 噪声 | 68 |

### 2.3 SPA 路由（最多 40 条）
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

### 2.4 API 候选端点（最多 40 条）
- `/api/Addresss`
- `/api/BasketItems`
- `/api/Cards`
- `/api/Challenges`
- `/api/Challenges/?key=nftMintChallenge`
- `/api/Challenges?id=probe`
- `/api/Challenges?name=probe`
- `/api/Challenges?q=probe`
- `/api/Challenges?query=probe`
- `/api/Challenges?search=probe`
- `/api/Complaints`
- `/api/Deliverys`
- `/api/Deliverys?id=probe`
- `/api/Deliverys?name=probe`
- `/api/Deliverys?q=probe`
- `/api/Deliverys?query=probe`
- `/api/Deliverys?search=probe`
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
- ... 其余 12 项省略

## 3. 漏洞概览
### 3.1 按严重级别统计
| 严重级别 | 数量 |
| --- | --- |
| 严重 | 1 |
| 高危 | 0 |
| 中危 | 0 |
| 低危 | 0 |
| 信息 | 0 |

### 3.2 按漏洞类型统计
| 漏洞类型 | 数量 |
| --- | --- |
| AUTH_BYPASS | 1 |

## 4. 漏洞详情
### 4.1 [严重] AUTH_BYPASS
- 路径：`/rest/user/login`
- 参数：`email`
- 注入位置：`body_json`
- Payload：`' OR 1=1--`
- 证据：login bypass succeeded: baseline status=401, bypass status=200, response contains auth token
- 响应：状态码=200，类型=application/json; charset=utf-8，耗时=40 ms

## 5. 修复建议
- 认证与登录链路加入失败次数限制、MFA、会话绑定与异常登录告警。