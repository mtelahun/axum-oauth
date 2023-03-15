import { InMemoryDatabase } from './lib/db';
import type { SessionData } from './lib/db';

export const session_db = new InMemoryDatabase<SessionData>();
