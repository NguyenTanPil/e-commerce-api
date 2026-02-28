import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, map } from 'rxjs';
import { RESPONSE_MESSAGE } from 'src/common/decorators/response.decorator';

@Injectable()
export class ResponseInterceptor implements NestInterceptor {
  constructor(private reflector: Reflector) {}
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const message = this.reflector.get<string>(RESPONSE_MESSAGE, context.getHandler()) || 'OK'
    return next.handle().pipe(
      map((data) => ({
        success: true,
        message,
        data
      }))
    );
  }
}
