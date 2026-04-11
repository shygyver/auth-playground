import {
  JoseJwksAuthority,
  JwksRotator
} from "@saurbit/oauth2-jwt";
import { jwksStore, rotationTimestampStore } from "./stores";

const jwksAuthority = new JoseJwksAuthority(jwksStore, 8.64e6); // 100-day key lifetime

await jwksAuthority.generateKeyPair()

const jwksRotator = new JwksRotator({
  keyGenerator:jwksAuthority,
  rotatorKeyStore: rotationTimestampStore,
  rotationIntervalMs: 7.884e9, // 91 days
});