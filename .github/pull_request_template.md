## 🎯 Objetivo deste Pull Request

Descreva as alterações realizadas na camada de Autenticação Zero-Trust (In-Memory JWT / HttpOnly Cookie), RBAC ou Acessibilidade WCAG 2.1 AA.

---

## 🔒 Checklist de Governança & Segurança

- [ ] **Zero-Leak Policy:** Nenhum arquivo `.env` ou segredo JWT real foi adicionado ao stage.
- [ ] **Zero LocalStorage:** O Access Token permanece isolado exclusivamente em memória RAM (Closure/Context).
- [ ] **Refresh Token Rotation:** O Cookie `fortress_rt` mantém as flags `HttpOnly`, `SameSite=Strict` e detecção de reuso.
- [ ] **Acessibilidade WCAG 2.1 AA:** Navegação por teclado, foco visível e `aria-live` preservados.
- [ ] **Testes & TypeScript:** `npm run typecheck` e `npm test` passam sem erros.
