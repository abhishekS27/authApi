/* eslint-disable prettier/prettier */
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable } from '@nestjs/common';
import { jwtConstants } from './constants';

//This strategy requires some initialization, so we do that by passing in an options object in the super() call.

//jwtFromRequest: supplies the method by which the JWT will be extracted from the Request. 
//We will use the standard approach of supplying a bearer token in the Authorization header of our API requests.

//ignoreExpiration: just to be explicit, we choose the default false setting, which delegates the responsibility of 
//ensuring that a JWT has not expired to the Passport module. This means that if our route is supplied with an expired JWT, 
//the request will be denied and a 401 Unauthorized response sent. Passport conveniently handles this automatically for us.
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtConstants.secret,
    });
  }

  async validate(payload: any) {
    return { userId: payload.sub, username: payload.username };
  }
}