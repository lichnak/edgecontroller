/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019-2020 Intel Corporation
 */

import React, { Component } from 'react';
import { withStyles } from '@material-ui/core/styles';
import {
  Table,
  TableBody,
  TableCell,
  TableRow,
  Button,
  Paper,
} from '@material-ui/core';

const CONTROLLER_URL = process.env.REACT_APP_CONTROLLER_UI_URL
const CUPS_URL = process.env.REACT_APP_CUPS_UI_URL
const CNCA_URL = process.env.REACT_APP_CNCA_UI_URL

const styles = theme => ({
  paper: {
    marginTop: theme.spacing(3),
    marginBottom: theme.spacing(3),
    padding: theme.spacing(2),
    [theme.breakpoints.up(600 + theme.spacing(3) * 2)]: {
      marginTop: theme.spacing(6),
      marginBottom: theme.spacing(6),
      padding: theme.spacing(3),
    },
  },
});

class Landing extends Component {
  _isMounted = false;

  constructor(props) {
    super(props);

    this.state = {
      loaded: false,
      hasError: false,
    }
  }

  _cancelIfUnmounted = (action) => {
    if (this._isMounted) {
      action();
    }
  }

  componentWillUnmount() {
    // Signal to cancel any pending async requests to prevent setting state
    // on an unmounted component.
    this._isMounted = false;
  }

  async componentDidMount() {
    this._isMounted = true;
  }

  render() {
    const {
      classes,
    } = this.props;

    const {
      hasError,
      error,
    } = this.state;

    if (hasError) {
      throw error;
    }

    const LandingChoiceTableRow = ({ match, history, item }) => {
      return (
        <TableRow>
          <TableCell>
            <Button
              onClick={() => window.location.assign(`${CONTROLLER_URL}/`)}
              variant="outlined"
              color="primary"
            >
              Infrastructure Manager
            </Button>
          </TableCell>
          <TableCell>
            <Button
              onClick={() => window.location.assign(`${CUPS_URL}/`)}
              variant="outlined"
              color="primary"
            >
              LTE CUPS Core Network
            </Button>
          </TableCell>
          <TableCell>
            <Button
              onClick={() => window.location.assign(`${CNCA_URL}/`)}
              variant="outlined"
              color="primary"
            >
              5G Next-Gen Core Network
            </Button>
          </TableCell>
        </TableRow>
      );
    }

    return (
      <div>
        <Paper className={classes.paper}>
          <Table>
            <TableBody>
              {
                <LandingChoiceTableRow/>
              }
            </TableBody>
          </Table>
        </Paper>
      </div>
    );
  }
};

export default withStyles(styles)(Landing);
