// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2019-2020 Intel Corporation

import React from 'react';
import PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import TextField from '@material-ui/core/TextField';
import Typography from '@material-ui/core/Typography';
import Button from '@material-ui/core/Button';

const styles = theme => ({
  container: {
    display: 'flex',
    flexWrap: 'wrap',
  },
  textField: {
    marginLeft: theme.spacing(),
    marginRight: theme.spacing(),
    width: 200,
  },
  fieldSet: {
    width: "100%",
  },
  dense: {
    marginTop: 19,
  },
  menu: {
    width: 200,
  },
  spacer: {
    width: "100%",
    padding: 20,
  }
});


class SourceForm extends React.Component {

  handleChange = name => event => {
    this.setState({ [name]: event.target.value });
  };

  render() {
    const { classes } = this.props;

    return (
      <form className={classes.container} noValidate autoComplete="off">
        <Typography variant="h6" className={classes.fieldSet} gutterBottom>
          Mac Filter
        </Typography>
                
        <TextField
          required
          id="standard-name"
          label="Description"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <TextField
          required
          id="standard-type"
          label="Target Action"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <TextField
          required
          id="standard-host"
          label="MAC Modifier"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <TextField
          required
          id="standard-error"
          label="IP Modifier"
          className={classes.textField}
          margin="normal"
        />

        <div className={classes.spacer}></div>

        <Button variant="contained" color="secondary" className={classes.button}>
          Submit
        </Button>
      </form>
    );
  }
}

SourceForm.propTypes = {
  classes: PropTypes.object.isRequired,
};

export default withStyles(styles)(SourceForm);
