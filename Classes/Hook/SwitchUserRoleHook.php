<?php
namespace IchHabRecht\BegroupsRoles\Hook;

/***************************************************************
 *  Copyright notice
 *
 *  (c) 2016 Nicole Cordes <cordes@cps-it.de>, CPS-IT GmbH
 *
 *  All rights reserved
 *
 *  This script is part of the TYPO3 project. The TYPO3 project is
 *  free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The GNU General Public License can be found at
 *  http://www.gnu.org/copyleft/gpl.html.
 *
 *  This script is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

use TYPO3\CMS\Core\Authentication\BackendUserAuthentication;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Type\Bitmask\Permission;
use TYPO3\CMS\Core\Utility\GeneralUtility;

/**
 * Sets current user group
 */
class SwitchUserRoleHook
{
    const SIGNAL_PreSwitchUserRole = 'preSwitchUserRole';

    /**
     * Assign user group from session data
     */
    public function setUserGroup()
    {
        $backendUser = $this->getBackendUser();

        if (empty($backendUser->user['tx_begroupsroles_enabled'])) {
            return;
        }

        $role = $backendUser->getSessionData('tx_begroupsroles_role');
        if ($role === null) {
            $role = 0;
            $backendUser->user['tx_begroupsroles_groups'] = implode(',', $this->getUsergroups($backendUser->user[$backendUser->usergroup_column]));
            GeneralUtility::makeInstance(ConnectionPool::class)
                ->getConnectionForTable($backendUser->user_table)
                ->update(
                    $backendUser->user_table,
                    [
                        'tx_begroupsroles_groups' => $backendUser->user['tx_begroupsroles_groups'],
                    ],
                    [
                        'uid' => $backendUser->user['uid'],
                    ]
                );
        }
        if (empty($role) && !empty($backendUser->user['tx_begroupsroles_limit'])) {
            $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
                ->getQueryBuilderForTable($backendUser->usergroup_table);
            $group = $queryBuilder
                ->select('uid')
                ->from($backendUser->usergroup_table)
                ->where(
                    $queryBuilder->expr()->in('uid', GeneralUtility::intExplode(',', $backendUser->user['tx_begroupsroles_groups']))
                )
                ->getConcreteQueryBuilder()->addOrderBy(
                    'FIND_IN_SET(' . $queryBuilder->quoteIdentifier('uid') . ', ' . $queryBuilder->quote($backendUser->user['tx_begroupsroles_groups']) . ')'
                )
                ->setMaxResults(1)
                ->execute()
                ->fetch();
            $role = !empty($group) ? $group['uid'] : 0;
        }
        if (!empty($role) && GeneralUtility::inList($backendUser->user['tx_begroupsroles_groups'], $role)) {
            $backupRole = $role;
            $signalSlotDispatcher = GeneralUtility::makeInstance(\TYPO3\CMS\Extbase\SignalSlot\Dispatcher::class);
            $signalSlotDispatcher->dispatch(
                __CLASS__,
                static::SIGNAL_PreSwitchUserRole,
                [
                    'backendUser' => $backendUser,
                    'role' => &$role,
                ]
            );
            $backendUser->user[$backendUser->usergroup_column] = $role;
            $role = $backupRole;
            if (!empty($backendUser->user['admin'])) {
                $backendUser->user['options'] |= Permission::PAGE_SHOW | Permission::PAGE_EDIT;
                $backendUser->user['admin'] = 0;
            }
        } else {
            $role = 0;
        }
        $backendUser->setAndSaveSessionData('tx_begroupsroles_role', $role);
    }

    /**
     * @param string $groupList
     * @param array $processedUsergroups
     * @return array
     */
    protected function getUsergroups($groupList, array $processedUsergroups = [])
    {
        $backendUser = $this->getBackendUser();
        $groupList = GeneralUtility::intExplode(',', $groupList, true);

        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable($backendUser->usergroup_table);
        $statement = $queryBuilder
            ->select('uid', 'subgroup')
            ->from($backendUser->usergroup_table)
            ->where(
                $queryBuilder->expr()->eq('pid', 0),
                $queryBuilder->expr()->in('uid', $groupList),
                $queryBuilder->expr()->orX(
                    $queryBuilder->expr()->eq('lockToDomain', $queryBuilder->quote('')),
                    $queryBuilder->expr()->isNull('lockToDomain'),
                    $queryBuilder->expr()->eq('lockToDomain', $queryBuilder->createNamedParameter(GeneralUtility::getIndpEnv('HTTP_HOST'), \PDO::PARAM_STR))
                )
            )
            ->execute();

        $usergroups = [];
        while (($row = $statement->fetch()) !== false) {
            if (!isset($processedUsergroups[$row['uid']])) {
                $processedUsergroups[$row['uid']] = $row['uid'];
                $usergroups[$row['uid']] = $row['uid'];
                if (!empty($row['subgroup'])) {
                    $subgroupList = GeneralUtility::intExplode(',', $row['subgroup'], true);
                    $subgroups = $this->getUsergroups($row['subgroup'], $processedUsergroups);
                    if (!empty($subgroups)) {
                        $usergroups = array_merge(
                            $usergroups,
                            array_intersect($subgroupList, $subgroups),
                            array_diff($subgroups, $subgroupList)
                        );
                    }
                }
            }
        }

        return $usergroups;
    }

    /**
     * @return BackendUserAuthentication
     */
    protected function getBackendUser()
    {
        return $GLOBALS['BE_USER'];
    }
}
