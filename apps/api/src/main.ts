import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

function buildDatabaseUrlFromParts() {
  const host = process.env.DB_HOST;
  const db = process.env.DB_NAME;
  const user = process.env.DB_USER;
  const password = process.env.DB_PASSWORD;
  const port = process.env.DB_PORT ?? '3306';

  if (!host || !db || !user || password == null) return null;
  return `mysql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${db}`;
}

async function bootstrap() {
  const built = buildDatabaseUrlFromParts();
  if (built) process.env.DATABASE_URL = built;

  const app = await NestFactory.create(AppModule);

  app.enableCors({
    origin: true,
    credentials: true,
  });
  await app.listen(process.env.PORT ? Number(process.env.PORT) : 4000);
}
bootstrap();
