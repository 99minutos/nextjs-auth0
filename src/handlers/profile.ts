import { NextApiResponse, NextApiRequest } from 'next';
import { ClientFactory } from '../auth0-session';
import { SessionCache, Session, fromJson, GetAccessToken } from '../session';
import { assertReqRes } from '../utils/assert';

export type AfterRefetch = (req: NextApiRequest, res: NextApiResponse, session: Session) => Promise<Session> | Session;

/**
 * Custom options for {@link HandleProfile}
 *
 * @category Server
 */
export type ProfileOptions = {
  /**
   * If set to `true` this will refetch the user profile information from `/userinfo` and save it to the session.
   */
  refetch?: boolean;

  /**
   * Like {@AfterCallback} when a session is created, you can use this function to validate or add/remove claims
   * after the session is updated. Will only run if {@link ProfileOptions.refetch} is `true`
   */
  afterRefetch?: AfterRefetch;
};

/**
 * The handler for the `/api/auth/me` route.
 *
 * @category Server
 */
export type HandleProfile = (req: NextApiRequest, res: NextApiResponse, options?: ProfileOptions) => Promise<void>;

/**
 * @ignore
 */
export default function profileHandler(
  getClient: ClientFactory,
  getAccessToken: GetAccessToken,
  sessionCache: SessionCache
): HandleProfile {
  return async (req, res, options): Promise<void> => {
    assertReqRes(req, res);

    if (!sessionCache.isAuthenticated(req, res)) {
      res.status(401).json({
        error: 'not_authenticated',
        description: 'The user does not have an active session or is not authenticated'
      });
      return;
    }

    const session = sessionCache.get(req, res) as Session;
    res.setHeader('Cache-Control', 'no-store');

    if (options?.refetch) {
      const { accessToken } = await getAccessToken(req, res);
      if (!accessToken) {
        throw new Error('No access token available to refetch the profile');
      }

      const client = await getClient();
      const userInfo = await client.userinfo(accessToken);
      let additionalInfo = {};
      let permissionsInfo = {};

      try {
        console.log('FETCHING');
        additionalInfo = await fetch(process.env.CLAIMS_URL || '', {
          method: 'POST',
          body: JSON.stringify(userInfo)
        });
      } catch (e) {
        console.log('ERROR WHILE FETCHING');
      }

      try {
        console.log('FETCHING PERMISSION URL');
        permissionsInfo = await fetch(process.env.AUTH0_PERMISSIONS_URL || '', {
          method: 'POST',
          body: JSON.stringify({ mixed_id: session.user.email })
        }).then((res) => res.json());
      } catch (e) {
        console.log('ERROR WHILE FETCHING PERMISSION URL');
      }

      let newSession = fromJson({
        ...session,
        user: {
          ...session.user,
          ...userInfo,
          ...additionalInfo,
          permissions: permissionsInfo
        }
      }) as Session;

      if (options.afterRefetch) {
        newSession = await options.afterRefetch(req, res, newSession);
      }

      sessionCache.set(req, res, newSession);

      res.json(newSession.user);
      return;
    }

    res.json(session.user);
  };
}
