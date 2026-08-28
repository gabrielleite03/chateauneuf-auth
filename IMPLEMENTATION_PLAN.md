# Plano de implementação

## Etapa 1: análise e documentação

- revisar o requisito de External Portal Server do Omada;
- confirmar hipótese de fluxo: cliente → Wi-Fi → gateway → redirecionamento → portal Go → login → autorização do cliente no Controller;
- registrar os pontos de integração que variam por versão do Omada e isolamento do contrato dentro do adapter;
- criar `ARCHITECTURE.md` com os princípios e desenho da solução.

## Etapa 2: estrutura do projeto Go

- inicializar módulo Go;
- criar estrutura de diretórios com camadas de domínio, aplicação, ports e adapters;
- criar `cmd/api` e `cmd/hashpassword`;
- criar arquivos de configuração e exemplos de ambiente.

## Etapa 3: domínio e regras de autenticação

- definir `User`, `Client` e `PortalSession`;
- implementar `UserRepository` e `NetworkAuthorizer` como ports;
- implementar `AuthService` com:
  - validação de sessão;
  - autenticação de usuário;
  - autorização do cliente;
  - proteção de replay e sessão expirada.

## Etapa 4: persistência local e geração de hash

- criar repositório local usando arquivo JSON/JSONL de usuários de desenvolvimento;
- usar bcrypt para hash de senha;
- criar `go run ./cmd/hashpassword` para gerar hashes;
- garantir que senhas nunca fiquem em texto puro no código.

## Etapa 5: transporte HTTP e portal

- criar router com endpoints:
  - `GET /portal`
  - `POST /portal/authenticate`
  - `POST /logout`
  - `GET /health`
  - `GET /ready`
- usar template HTML responsivo e local para login;
- criar sessão do portal com identificador aleatório, TTL curto e dados do cliente;
- validar `redirectUrl` de forma segura;
- aplicar rate limiting e headers HTTP de segurança.

## Etapa 6: adapter Omada

- criar um cliente HTTP dedicado e isolado em `internal/adapters/omada`;
- manter autenticação e autorização encapsuladas no adapter;
- tratar:
  - login no Controller;
  - manutenção de sessão;
  - CSRF token quando exigido pela versão;
  - timeout e erros HTTP;
  - erros de resposta do Controller;
  - TLS com `OMADA_TLS_INSECURE=false` por padrão.
- todas as diferenças de versão do Controller devem ficar aqui.

## Etapa 7: testes

- unit tests para `AuthService` cobrindo:
  - usuário válido;
  - senha inválida;
  - usuário inexistente;
  - usuário desabilitado;
  - sessão expirada;
  - reutilização de sessão;
  - erro de comunicação com Omada;
  - Omada rejeitando autorização;
  - autenticação bem-sucedida.
- testes de HTTP handler com `httptest`;
- teste do adapter Omada com `httptest.Server`.

## Etapa 8: empacotamento e execução

- criar `Dockerfile` multi-stage;
- criar `docker-compose.yml` para desenvolvimento;
- criar `Makefile` com comandos de build/test;
- criar README detalhado com fluxo e instruções.

## Entregáveis finais

A implementação final deve permitir:

1. executar `go test ./...` com sucesso;
2. executar `go run ./cmd/api` em desenvolvimento local;
3. executar `docker compose up -d` para ambiente dev;
4. autenticar clientes via captive portal com segurança e sem expor endpoints administrativos sem autenticação.

## Observações de risco

- a integração real do Omada Controller depende do contrato exato da sua versão e da sua configuração de Controller Mode;
- o adapter deve ser configurável para a versão do Controller e não assumir endpoints inventados;
- diferenças de `site`, `controllerId`, `csrf` e redirecionamento devem ser tratadas como adaptações do adapter e documentadas.
