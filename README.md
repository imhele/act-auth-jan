# act-auth-jan

See [act-auth/act-auth](https://github.com/act-auth/act-auth).

## ActAuth Jan V1 sign

```ts
import ActAuthJan from '@imhele/act-auth-jan';

const id = 'id';
const key = await db.query({ id });
const signature = ActAuthJan.createV1Sign(key, id, Math.trunc(Date.now() / 1000 + 7200));
// 'FZEMjpbWZxpBP6fozW6m8VZ6Fjrf68wZNP23EWdhCXY=F6mbyMFpZA=='

const parsed = ActAuthJan.parseV1Sign(
  'FZEMjpbWZxpBP6fozW6m8VZ6Fjrf68wZNP23EWdhCXY=F6mbyMFpZA=='
);
// parsed: {
//   signtype: 1,
//   expireat: 1587965731,
//   id: <Buffer 69 64>,
//   hashvalue: 'FZEMjpbWZxpBP6fozW6m8VZ6Fjrf68wZNP23EWdhCXY='
// }
if (!parsed) throw new Error('invalid signature');
if (parsed.expireat < Date.now() / 1000) throw new Error('signature expired');
const key = await db.query({ id: parsed.id.toString() }); // 'key'
if (parsed.hashvalue !== ActAuthJan.getHashvalue(key, parsed.id, parsed.expireat))
  throw new Error('invalid signature');
```

## ActAuth Jan V2 sign

```ts
import ActAuthJan from '@imhele/act-auth-jan';

const id = 'id';
const key = await db.query({ id });
const policy = { id, ps: 'hello' };
const signature = ActAuthJan.createV2Sign(key, policy, Math.trunc(Date.now() / 1000 + 7200));
// 'Bj23YXd1+loN1crTPkMaBbgEsuvws324ssqbMCWTJIc=F6mcOEJ7ImlkIjoiaWQiLCJwcyI6ImhlbGxvIn0='

const parsed = ActAuthJan.parseV2Sign(
  'Bj23YXd1+loN1crTPkMaBbgEsuvws324ssqbMCWTJIc=F6mcOEJ7ImlkIjoiaWQiLCJwcyI6ImhlbGxvIn0='
);
// parsed: {
//   signtype: 2,
//   expireat: 1587966177,
//   policy: { id: 'id', ps: 'hello' },
//   hashvalue: 'Bj23YXd1+loN1crTPkMaBbgEsuvws324ssqbMCWTJIc='
// }
```
