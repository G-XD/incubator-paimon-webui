/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.paimon.web.server.service.impl;

import org.apache.paimon.web.server.data.dto.LoginDto;
import org.apache.paimon.web.server.data.enums.UserType;
import org.apache.paimon.web.server.data.model.User;
import org.apache.paimon.web.server.data.result.exception.BaseException;
import org.apache.paimon.web.server.data.result.exception.user.UserDisabledException;
import org.apache.paimon.web.server.data.result.exception.user.UserEmailDuplicateException;
import org.apache.paimon.web.server.data.result.exception.user.UserNameDuplicateException;
import org.apache.paimon.web.server.data.result.exception.user.UserNotExistsException;
import org.apache.paimon.web.server.data.result.exception.user.UserPasswordNotMatchException;
import org.apache.paimon.web.server.data.result.exception.user.UserPhoneDuplicateException;
import org.apache.paimon.web.server.mapper.UserMapper;
import org.apache.paimon.web.server.mapper.UserRoleMapper;
import org.apache.paimon.web.server.service.LdapService;
import org.apache.paimon.web.server.service.UserService;

import cn.dev33.satoken.secure.SaSecureUtil;
import cn.dev33.satoken.stp.StpUtil;
import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.baomidou.mybatisplus.core.metadata.IPage;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/** UserServiceImpl. */
@Service
public class UserServiceImpl extends ServiceImpl<UserMapper, User> implements UserService {

    @Autowired private LdapService ldapService;
    @Autowired private UserMapper userMapper;
    @Autowired private UserRoleMapper userRoleMapper;

    /**
     * login by username and password.
     *
     * @param loginDto login info
     * @return {@link String}
     */
    @Override
    public String login(LoginDto loginDto) throws BaseException {
        String username = loginDto.getUsername();
        String password = loginDto.getPassword();

        User user =
                loginDto.isLdapLogin()
                        ? ldapLogin(username, password)
                        : localLogin(username, password);
        if (!user.getEnabled()) {
            throw new UserDisabledException();
        }

        StpUtil.login(user.getId(), loginDto.isRememberMe());

        return StpUtil.getTokenValue();
    }

    private User localLogin(String username, String password) throws BaseException {
        User user =
                this.lambdaQuery()
                        .eq(User::getUsername, username)
                        .eq(User::getUserType, UserType.LOCAL.getCode())
                        .one();
        if (user == null) {
            throw new UserNotExistsException();
        }
        if (!user.getPassword().equals(SaSecureUtil.md5(password))) {
            throw new UserPasswordNotMatchException();
        }
        return user;
    }

    private User ldapLogin(String username, String password) throws BaseException {
        Optional<User> authenticate = ldapService.authenticate(username, password);
        if (!authenticate.isPresent()) {
            throw new UserPasswordNotMatchException();
        }

        User user =
                this.lambdaQuery()
                        .eq(User::getUsername, username)
                        .eq(User::getUserType, UserType.LDAP.getCode())
                        .one();
        if (user == null) {
            user = authenticate.get();
            this.save(user);
            // TODO assign default roles and tenants
        }
        return user;
    }

    /**
     * Query the list of assigned user roles.
     *
     * @param user query params
     * @return user list
     */
    @Override
    public List<User> selectAllocatedList(User user) {
        return userMapper.selectAllocatedList(user);
    }

    /**
     * Query the list of unassigned user roles.
     *
     * @param user query params
     * @return user list
     */
    @Override
    public List<User> selectUnallocatedList(User user) {
        return userMapper.selectUnallocatedList(user);
    }

    /**
     * Paging and querying user data based on conditions.
     *
     * @param page page params
     * @param user query params
     * @return user list
     */
    @Override
    public List<User> selectUserList(IPage<User> page, User user) {
        LambdaQueryWrapper<User> queryWrapper =
                new LambdaQueryWrapper<User>()
                        .eq(user.getUserType() != null, User::getUserType, user.getUserType())
                        .like(
                                StringUtils.isNotBlank(user.getEmail()),
                                User::getEmail,
                                user.getEmail())
                        .like(
                                StringUtils.isNotBlank(user.getNickname()),
                                User::getNickname,
                                user.getNickname())
                        .like(
                                StringUtils.isNotBlank(user.getUsername()),
                                User::getUsername,
                                user.getUsername());
        List<User> result = this.page(page, queryWrapper).getRecords();
        result.forEach(u -> u.setPassword(null));
        return result;
    }

    /**
     * Reset password.
     *
     * @param user user info
     * @return result
     */
    @Override
    public boolean resetPwd(User user) {
        return this.lambdaUpdate()
                .set(User::getPassword, SaSecureUtil.md5(user.getPassword()))
                .eq(User::getId, user.getId())
                .update();
    }

    /**
     * Add user.
     *
     * @param user user info
     * @return result
     */
    @Override
    public boolean addUser(User user) throws BaseException {
        this.checkUserUnique(user);
        user.setPassword(SaSecureUtil.md5(user.getPassword()));
        return this.save(user);
    }

    /**
     * Update user.
     *
     * @param user user info
     * @return result
     */
    @Override
    public boolean updateUser(User user) {
        this.checkUserUnique(user);
        return userMapper.updateUser(user) > 0;
    }

    /**
     * Deletes the users with the specified user IDs.
     *
     * @param userIds the list of user IDs to delete
     * @return true if the users were successfully deleted, false otherwise
     */
    @Override
    @Transactional(rollbackFor = Exception.class)
    public boolean deleteUsers(Integer[] userIds) {
        userRoleMapper.deleteUserRole(userIds);
        return this.removeBatchByIds(Arrays.stream(userIds).collect(Collectors.toList()));
    }

    public void checkUserUnique(User user) {
        if (StringUtils.isNotBlank(user.getUsername())
                && this.lambdaQuery().eq(User::getUsername, user.getUsername()).count() > 0) {
            throw new UserNameDuplicateException();
        }
        if (StringUtils.isNotBlank(user.getEmail())
                && this.lambdaQuery().eq(User::getEmail, user.getEmail()).count() > 0) {
            throw new UserEmailDuplicateException();
        }
        if (StringUtils.isNotBlank(user.getMobile())
                && this.lambdaQuery().eq(User::getMobile, user.getMobile()).count() > 0) {
            throw new UserPhoneDuplicateException();
        }
    }
}
