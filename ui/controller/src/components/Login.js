// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

import React, { Component } from 'react';
import withStyles from '@material-ui/core/styles/withStyles';
import { withRouter } from 'react-router-dom'
import CssBaseline from '@material-ui/core/CssBaseline';
import Typography from '@material-ui/core/Typography';
import Grid from '@material-ui/core/Grid';
import Paper from '@material-ui/core/Paper';
import Button from '@material-ui/core/Button';
import FormControl from '@material-ui/core/FormControl';
import FormHelperText from '@material-ui/core/FormHelperText';
import Avatar from '@material-ui/core/Avatar';
import Input from '@material-ui/core/Input';
import InputLabel from '@material-ui/core/InputLabel';
import LockOutlinedIcon from '@material-ui/icons/LockOutlined';
import Auth from './Auth';

const numeral = require('numeral');

numeral.defaultFormat('0');
const styles = theme => ({
  root: {
    flexGrow: 1,
    backgroundColor: theme.palette.secondary['A100'],
    overflow: 'hidden',
    backgroundSize: 'cover',
    backgroundPosition: '0 400px',
    marginTop: 10,
    padding: 20,
    paddingBottom: 500
  },
  grid: {
    margin: `0 ${theme.spacing(2)}px`
  },
  smallContainer: {
    width: '60%'
  },
  bigContainer: {
    width: '80%'
  },
  stepContainer: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center'
  },
  stepGrid: {
    width: '80%'
  },
  buttonBar: {
    marginTop: 10,
    display: 'flex',
    justifyContent: 'center'
  },
  button: {
    backgroundColor: theme.palette.primary['A100']
  },
  paper: {
    padding: theme.spacing(3),
    textAlign: 'left',
    color: theme.palette.text.secondary
  },
  topInfo: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 42
  },
  formControl: {
    width: '100%'
  },
  loginBox: {
    minHeight: "5rem",
  },
});

class LoginForm extends Component {
  handleInputChange = event => {
    this.setState({ [event.target.name]: event.target.value });
  };

  handleLogin = event => {
    event.preventDefault();

    const { username, password } = this.state;

    Auth.login(username, password)
      .then(({ success, errorText }) => {
        if (success) {
          this.props.history.push('/');
          return;
        }

        this.setState({ loginError: true, helperText: errorText })
      });
  };


  constructor(props) {
    super(props);
    this.state = {
      loginError: false,
      helperText: ""
    };

    // This binding is necessary to make `this` work in the callback
    this.handleInputChange = this.handleInputChange.bind(this);
    this.handleLogin = this.handleLogin.bind(this);
  }

  render() {
    const { classes } = this.props;

    return (
      <React.Fragment>
        <CssBaseline />
        <div className={classes.root}>
          <Grid container justify="center">
            <Grid spacing={24} alignItems="center" justify="center" container className={classes.grid}>
              <Grid item xs={12} lg={6}>
                <div className={classes.stepContainer}>
                  <div className={classes.smallContainer}>
                    <main className={classes.main}>
                      <CssBaseline />
                      <Paper className={classes.paper}>
                        <Avatar className={classes.avatar}>
                          <LockOutlinedIcon />
                        </Avatar>
                        <Typography component="h1" variant="h5">
                          Controller Login
                        </Typography>
                        <form onSubmit={this.handleLogin} className={classes.form} autoComplete="off">
                          <FormControl margin="normal" required fullWidth>
                            <InputLabel htmlFor="username">Username</InputLabel>
                            <Input error={this.state.loginError} id="username" name="username" autoComplete="off" onChange={this.handleInputChange} autoFocus />
                          </FormControl>
                          <FormControl className={classes.loginBox} margin="normal" required fullWidth>
                            <InputLabel htmlFor="password">Password</InputLabel>
                            <Input error={this.state.loginError} aria-describedby="component-error-text" name="password" type="password" id="password" onChange={this.handleInputChange} autoComplete="off" />

                            {this.state.helperText !== "" ?
                              <FormHelperText id="component-error-text">
                                {this.state.helperText}
                              </FormHelperText> : null
                            }

                          </FormControl>
                          <Button
                            type="submit"
                            fullWidth
                            variant="contained"
                            color="primary"
                            className={classes.buttonBar}
                          >
                            Sign in
                          </Button>
                        </form>
                      </Paper>
                    </main>
                  </div>
                </div>
              </Grid>
            </Grid>
          </Grid>
        </div>
      </React.Fragment>
    )
  }
}

export default withRouter(withStyles(styles)(LoginForm))
